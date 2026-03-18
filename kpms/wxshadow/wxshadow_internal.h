/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * W^X Shadow Memory KPM Module - Internal Header
 * Copyright (C) 2024
 */

#ifndef _KPM_WXSHADOW_INTERNAL_H_
#define _KPM_WXSHADOW_INTERNAL_H_

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <hook.h>
#include <ksyms.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/rculist.h>
/* init_task: use wx_init_task via kallsyms (framework doesn't export it) */
#include <pgtable.h>
#include <asm/current.h>
#include <syscall.h>
#include <kputils.h>
#include <asm/ptrace.h>
#include <asm/atomic.h>
#include <linux/err.h>

#include <predata.h>
#include "wxshadow.h"

/* ========== ARM64 CPU helpers ========== */

static inline void cpu_relax(void)
{
    asm volatile("yield" ::: "memory");
}

/*
 * Per-page PTE rewrite lock.
 * This is a logical lock, not the kernel page-table lock: it serializes
 * wxshadow's own PTE transitions (shadow/original) for one page so
 * release/fault/step/GUP paths cannot race each other.
 */
static inline void wxshadow_page_pte_lock(struct wxshadow_page *page)
{
    while (atomic_cmpxchg(&page->pte_lock, 0, 1) != 0)
        cpu_relax();
}

static inline void wxshadow_page_pte_unlock(struct wxshadow_page *page)
{
    atomic_set(&page->pte_lock, 0);
}

/*
 * Use task_struct_offset from KernelPatch framework (linux/sched.h)
 * The framework provides: comm_offset, cred_offset, real_cred_offset, etc.
 * We need to detect: tasks_offset, mm_offset
 * For pid/tgid: use wxfunc(__task_pid_nr_ns)
 */

/*
 * Fixed next_task implementation.
 * The KP framework's next_task() in linux/sched.h has a bug:
 *   next - task_struct_offset.tasks_offset
 * This is pointer arithmetic, which multiplies by sizeof(struct list_head)=16.
 * Correct implementation uses (char*) for byte-level offset.
 */
static inline struct task_struct *wx_next_task(struct task_struct *task)
{
    struct list_head *head = (struct list_head *)((char *)task + task_struct_offset.tasks_offset);
    struct list_head *next = head->next;
    return (struct task_struct *)((char *)next - task_struct_offset.tasks_offset);
}

/* ========== Kernel function pointers ========== */

/* Memory management */
extern void *(*kfunc_find_vma)(void *mm, unsigned long addr);
extern void *(*kfunc_get_task_mm)(void *task);
extern void (*kfunc_mmput)(void *mm);
/* find_task_by_vpid: use find_task_by_vpid() from linux/sched.h */

/* exit_mmap hook */
extern void *kfunc_exit_mmap;

/* Page allocation */
extern unsigned long (*kfunc___get_free_pages)(unsigned int gfp_mask, unsigned int order);
extern void (*kfunc_free_pages)(unsigned long addr, unsigned int order);

/* Address translation */
extern s64 *kvar_memstart_addr;
extern s64 *kvar_physvirt_offset;
extern unsigned long page_offset_base;
extern s64 detected_physvirt_offset;
extern int physvirt_offset_valid;

/* Page table config */
extern int wx_page_shift;
extern int wx_page_level;

/*
 * wxshadow local function pointer macros (similar to KP's kfunc_def/kfunc_match)
 * Using wx_ prefix to avoid conflict with framework's kf_ symbols
 *
 * Usage:
 *   Declaration: extern void wxfunc_def(_raw_spin_lock)(raw_spinlock_t *lock);
 *   Definition:  void wxfunc_def(_raw_spin_lock)(raw_spinlock_t *lock) = 0;
 *   Lookup:      wxfunc_lookup_name(_raw_spin_lock);
 *   Call:        wxfunc(_raw_spin_lock)(lock);
 */
#define wxfunc(func) wx_##func
#define wxfunc_def(func) (*wx_##func)
/* Spinlock functions */
extern void wxfunc_def(_raw_spin_lock)(raw_spinlock_t *lock);
extern void wxfunc_def(_raw_spin_unlock)(raw_spinlock_t *lock);

/*
 * Override framework's spin_lock/spin_unlock to use our wxfunc symbols
 * This avoids undefined references to kf__raw_spin_lock/unlock
 */
#undef spin_lock
#undef spin_unlock
#undef raw_spin_lock
#undef raw_spin_unlock
#define raw_spin_lock(lock) wxfunc(_raw_spin_lock)(lock)
#define raw_spin_unlock(lock) wxfunc(_raw_spin_unlock)(lock)
#define spin_lock(lock) raw_spin_lock(&(lock)->rlock)
#define spin_unlock(lock) raw_spin_unlock(&(lock)->rlock)

/* Task functions */
extern struct task_struct *wxfunc_def(find_task_by_vpid)(pid_t nr);
extern pid_t wxfunc_def(__task_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns);

/* init_task - looked up via kallsyms since framework doesn't export it */
extern struct task_struct *wx_init_task;

/* Cache operations */
extern void (*kfunc_flush_dcache_page)(void *page);
extern void (*kfunc___flush_icache_range)(unsigned long start, unsigned long end);

/* Debug/ptrace */
extern void (*kfunc_user_enable_single_step)(void *task);
extern void (*kfunc_user_disable_single_step)(void *task);

/* Direct handler hook */
extern void *kfunc_brk_handler;
extern void *kfunc_single_step_handler;

/* register_user_*_hook API (fallback) */
extern void (*kfunc_register_user_break_hook)(struct wx_break_hook *hook);
extern void (*kfunc_register_user_step_hook)(struct wx_step_hook *hook);
extern spinlock_t *kptr_debug_hook_lock;

/* Locking - NOT USED (lockless operation) */

/* RCU */
extern void (*kfunc_rcu_read_lock)(void);
extern void (*kfunc_rcu_read_unlock)(void);
extern void (*kfunc_synchronize_rcu)(void);
extern void (*kfunc_kick_all_cpus_sync)(void);

/* Memory allocation */
extern void *(*kfunc_kzalloc)(size_t size, unsigned int flags);
extern void *(*kfunc_kcalloc)(size_t n, size_t size, unsigned int flags);
extern void (*kfunc_kfree)(void *ptr);

/* Safe memory access */
extern long (*kfunc_copy_from_kernel_nofault)(void *dst, const void *src, size_t size);

/* do_page_fault hook */
extern void *kfunc_do_page_fault;

/* follow_page_pte hook (GUP hiding) */
extern void *kfunc_follow_page_pte;

/* fork protection hooks */
extern void *kfunc_dup_mmap;
extern void *kfunc_uprobe_dup_mmap;
extern void *kfunc_copy_process;
extern void *kfunc_cgroup_post_fork;

/* TLB flush */
extern void (*kfunc_flush_tlb_page)(void *vma, unsigned long uaddr);
extern void (*kfunc___flush_tlb_range)(void *vma, unsigned long start, unsigned long end,
                                        unsigned long stride, bool last_level, int tlb_level);

/* THP split */
extern void (*kfunc___split_huge_pmd)(void *vma, void *pmd, unsigned long address,
                                       bool freeze, void *page);

/* ========== mm_struct offsets ========== */

extern int16_t vma_vm_mm_offset;
/* mm_pgd_offset: use mm_struct_offset.pgd_offset from KP framework (linux/mm_types.h) */
/* NOTE: mm_page_table_lock_offset and mm_mmap_lock_offset_dyn are NOT used (lockless) */

/* mm->context.id offset for ASID (detected at runtime) */
extern int16_t mm_context_id_offset;

/* TLB flush mode control */
extern int tlb_flush_mode;

/* ========== Global state ========== */

/* Use KP framework's spinlock_t and list_head from linux/spinlock.h and linux/list.h */
extern struct list_head page_list;      /* Global list of wxshadow_page */
extern spinlock_t global_lock;

/*
 * In-flight handler counter.
 * Incremented by each handler on entry, decremented on exit.
 * wxshadow_exit() waits for this to reach 0 after unhooking handlers
 * before returning — ensuring no module code is executing when KP calls
 * kp_free_exec(mod->start) immediately after exit() returns.
 */
extern atomic_t wx_in_flight;

#define WX_HANDLER_ENTER() atomic_inc(&wx_in_flight)
#define WX_HANDLER_EXIT()  atomic_dec(&wx_in_flight)

#define WXSHADOW_RELEASE_WAIT_LOOPS 2000000

/* init_task: use init_task from linux/init_task.h (KernelPatch framework) */

/* ========== BRK/Step hook ========== */
/* NOTE: Using direct brk_handler/single_step_handler hook, no struct needed */

/* ========== ESR parsing macros ========== */

#define ESR_ELx_EC_SHIFT        26
#define ESR_ELx_EC_MASK         (0x3FUL << ESR_ELx_EC_SHIFT)
#define ESR_ELx_EC(esr)         (((esr) & ESR_ELx_EC_MASK) >> ESR_ELx_EC_SHIFT)
#define ESR_ELx_IL_SHIFT        25
#define ESR_ELx_IL              (1UL << ESR_ELx_IL_SHIFT)
#define ESR_ELx_ISS_MASK        0x01FFFFFFUL
#define ESR_ELx_WNR_SHIFT       6
#define ESR_ELx_WNR             (1UL << ESR_ELx_WNR_SHIFT)
#define ESR_ELx_S1PTW_SHIFT     7
#define ESR_ELx_S1PTW           (1UL << ESR_ELx_S1PTW_SHIFT)
#define ESR_ELx_CM_SHIFT        8
#define ESR_ELx_CM              (1UL << ESR_ELx_CM_SHIFT)

#define ESR_ELx_EC_UNKNOWN      0x00
#define ESR_ELx_EC_IABT_LOW     0x20
#define ESR_ELx_EC_IABT_CUR     0x21
#define ESR_ELx_EC_DABT_LOW     0x24
#define ESR_ELx_EC_DABT_CUR     0x25

static inline bool is_el0_instruction_abort(unsigned int esr)
{
    return ESR_ELx_EC(esr) == ESR_ELx_EC_IABT_LOW;
}

static inline bool is_el0_data_abort(unsigned int esr)
{
    return ESR_ELx_EC(esr) == ESR_ELx_EC_DABT_LOW;
}

static inline bool is_permission_fault(unsigned int esr)
{
    unsigned int fsc = esr & 0x3F;
    return (fsc & 0x3C) == 0x0C;
}

enum wxshadow_fault_access {
    WXSHADOW_FAULT_NONE = 0,
    WXSHADOW_FAULT_EXEC,
    WXSHADOW_FAULT_READ,
    WXSHADOW_FAULT_WRITE,
};

static inline enum wxshadow_fault_access
wxshadow_classify_permission_fault(unsigned int esr)
{
    if (!is_permission_fault(esr))
        return WXSHADOW_FAULT_NONE;

    if (is_el0_instruction_abort(esr))
        return WXSHADOW_FAULT_EXEC;

    if (!is_el0_data_abort(esr))
        return WXSHADOW_FAULT_NONE;

    /*
     * Cache maintenance and stage-1 page-table walk faults are not direct
     * writes to the tracked page contents. Treat CM like a read-side access so
     * we can flip back to the original mapping, and ignore S1PTW entirely.
     */
    if (esr & ESR_ELx_S1PTW)
        return WXSHADOW_FAULT_NONE;
    if (esr & ESR_ELx_CM)
        return WXSHADOW_FAULT_READ;

    return (esr & ESR_ELx_WNR) ? WXSHADOW_FAULT_WRITE
                               : WXSHADOW_FAULT_READ;
}

/*
 * Use KP framework's spinlock and list from linux/spinlock.h and linux/list.h:
 * - spin_lock() / spin_unlock()
 * - INIT_LIST_HEAD() / list_add() / list_del_init() / list_empty()
 * - list_for_each() / list_for_each_safe()
 * - container_of() from linux/container_of.h
 */

/* ========== Kernel address validation ========== */

/*
 * is_kva - check if address is a valid kernel virtual address
 * ARM64 TTBR1 addresses have high 16 bits set to 0xffff
 */
static inline bool is_kva(unsigned long addr)
{
    return (addr >> 48) == 0xffff;
}

/* ========== Safe memory read helpers ========== */

/*
 * safe_read_u64 - safely read a u64 from kernel memory
 * Returns true on success, false if address is invalid or unreadable
 * Note: kfunc_copy_from_kernel_nofault is declared later in this file
 */
static inline bool safe_read_u64(unsigned long addr, u64 *out)
{
    extern long (*kfunc_copy_from_kernel_nofault)(void *dst, const void *src, size_t size);

    if (!is_kva(addr))
        return false;

    if (kfunc_copy_from_kernel_nofault) {
        if (kfunc_copy_from_kernel_nofault(out, (const void *)addr, sizeof(*out)) != 0)
            return false;
    } else {
        /* Fallback: direct access (less safe) */
        *out = *(u64 *)addr;
    }
    return true;
}

/*
 * safe_read_ptr - safely read a pointer from kernel memory
 */
static inline bool safe_read_ptr(unsigned long addr, void **out)
{
    return safe_read_u64(addr, (u64 *)out);
}

/* ========== VMA field helpers ========== */

#define VMA_VM_START_OFFSET     0x00
#define VMA_VM_END_OFFSET       0x08

#define GET_FIELD(ptr, offset, type) (*(type *)((char *)(ptr) + (offset)))
#define SET_FIELD(ptr, offset, type, val) (*(type *)((char *)(ptr) + (offset)) = (val))

static inline void *vma_mm(void *vma) {
    if (vma_vm_mm_offset < 0) {
        pr_err("wxshadow: vma_vm_mm_offset not initialized!\n");
        return NULL;
    }
    return GET_FIELD(vma, vma_vm_mm_offset, void *);
}

static inline unsigned long vma_start(void *vma) {
    return GET_FIELD(vma, VMA_VM_START_OFFSET, unsigned long);
}

static inline unsigned long vma_end(void *vma) {
    return GET_FIELD(vma, VMA_VM_END_OFFSET, unsigned long);
}

static inline void *mm_pgd(void *mm) {
    /* Use KP framework's mm_struct_offset.pgd_offset (linux/mm_types.h) */
    if (mm_struct_offset.pgd_offset < 0) {
        pr_err("wxshadow: mm_struct_offset.pgd_offset not initialized!\n");
        return NULL;
    }
    return GET_FIELD(mm, mm_struct_offset.pgd_offset, void *);
}

/* NOTE: mm_mmap_lock helper removed - lockless operation */

/* ========== Safe kcalloc wrapper ========== */

static inline void *safe_kcalloc(size_t n, size_t size, unsigned int flags)
{
    if (kfunc_kcalloc)
        return kfunc_kcalloc(n, size, flags);
    if (n != 0 && size > ((size_t)-1) / n)
        return NULL;
    return kfunc_kzalloc(n * size, flags);
}

/* ========== Address translation ========== */

static inline unsigned long vaddr_to_paddr_at(unsigned long vaddr)
{
    u64 par;
    asm volatile("at s1e1r, %0" : : "r"(vaddr));
    asm volatile("isb");
    asm volatile("mrs %0, par_el1" : "=r"(par));
    if (par & 1)
        return 0;
    return (par & 0x0000FFFFFFFFF000UL) | (vaddr & 0xFFF);
}

static inline unsigned long phys_to_virt_safe(unsigned long pa)
{
    if (physvirt_offset_valid)
        return pa + detected_physvirt_offset;
    else if (kvar_physvirt_offset)
        return pa + *kvar_physvirt_offset;
    else
        return (pa - *kvar_memstart_addr) + page_offset_base;
}

static inline unsigned long kaddr_to_phys(unsigned long vaddr)
{
    if (physvirt_offset_valid)
        return vaddr - detected_physvirt_offset;
    else if (kvar_physvirt_offset)
        return vaddr - *kvar_physvirt_offset;
    else
        return (vaddr - page_offset_base) + *kvar_memstart_addr;
}

static inline unsigned long kaddr_to_pfn(unsigned long vaddr)
{
    return kaddr_to_phys(vaddr) >> PAGE_SHIFT;
}

static inline void *pfn_to_kaddr(unsigned long pfn)
{
    unsigned long pa = pfn << PAGE_SHIFT;
    return (void *)phys_to_virt_safe(pa);
}

#define safe_kunmap(addr) do { } while(0)

/* ========== Cache operations ========== */

/*
 * wxshadow_flush_kern_dcache_area - clean dcache to PoU for a kernel VA range.
 *
 * After writing to a shadow page via kernel VA (memcpy / copy_from_user),
 * the dirty dcache lines must be cleaned to the Point of Unification so that
 * subsequent instruction fetches (via user VA) see the updated data.
 *
 * Using kernel VA for dc cvau is critical because:
 *  - The kernel VA is always mapped (TTBR1), so dc cvau never silently fails.
 *  - In cross-process patching (pid != 0), the target's user VA is NOT mapped
 *    in the calling process's TTBR0, so dc cvau at user VA would be a NOP.
 *  - dcache is PIPT, so cleaning by kernel VA cleans the same physical line
 *    that instruction fetch via user VA will access.
 */
static inline void wxshadow_flush_kern_dcache_area(unsigned long kva, unsigned long size)
{
    unsigned long addr, end;
    u64 ctr_el0, line_size;

    /* Read cache line size from CTR_EL0.DminLine */
    asm volatile("mrs %0, ctr_el0" : "=r"(ctr_el0));
    line_size = 4 << ((ctr_el0 >> 16) & 0xf);

    end = kva + size;
    for (addr = kva & ~(line_size - 1); addr < end; addr += line_size)
        asm volatile("dc cvau, %0" : : "r"(addr) : "memory");

    asm volatile("dsb ish" : : : "memory");
}

static inline void wxshadow_flush_icache_range(unsigned long start, unsigned long end)
{
    /* All callers pass user VA; dcache is already cleaned on the kernel VA
     * via wxshadow_flush_kern_dcache_area().  Just do global icache invalidate. */
    (void)start; (void)end;
    asm volatile("ic ialluis" : : : "memory");
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
}

static inline void wxshadow_flush_icache_page(unsigned long addr)
{
    wxshadow_flush_icache_range(addr & PAGE_MASK, (addr & PAGE_MASK) + PAGE_SIZE);
}

/* ========== Page table helpers ========== */

/* NOTE: mm_page_table_lock helper removed - lockless operation */
/* NOTE: mm_get_asid removed - using kernel flush_tlb_page directly */

/* ========== Core functions (wxshadow.c) ========== */

/*
 * wxshadow_page_put - release one reference to a page.
 * When refcount drops to zero the struct is kfree'd.
 * Safe to call from any context; acquires global_lock internally.
 */
void wxshadow_page_put(struct wxshadow_page *page);

struct wxshadow_page *wxshadow_find_page(void *mm, unsigned long addr);
struct wxshadow_page *wxshadow_create_page(void *mm, unsigned long page_addr);
void wxshadow_free_page(struct wxshadow_page *page);
struct wxshadow_bp *wxshadow_find_bp(struct wxshadow_page *page_info, unsigned long addr);
void wxshadow_sync_page_tracking(struct wxshadow_page *page);
int wxshadow_validate_page_mapping(void *mm, void *vma, struct wxshadow_page *page_info, unsigned long page_addr);
int wxshadow_teardown_page(struct wxshadow_page *page, const char *reason);
int wxshadow_teardown_pages_for_mm(void *mm, const char *reason);
int wxshadow_release_page_logically(struct wxshadow_page *page,
                                    const char *reason);
int wxshadow_release_pages_for_mm(void *mm, const char *reason);
int wxshadow_handle_write_fault(void *mm, unsigned long addr);
void wxshadow_sync_shadow_exec_zero(struct wxshadow_page *page,
                                    const char *reason);
void wxshadow_mark_patch_dirty(struct wxshadow_page *page, unsigned long offset,
                               unsigned long len);
void wxshadow_mark_bp_dirty(struct wxshadow_page *page, unsigned long offset);
void wxshadow_clear_bp_dirty(struct wxshadow_page *page, unsigned long offset);
bool wxshadow_page_has_patch_dirty(struct wxshadow_page *page);
void wxshadow_clear_page_tracking(struct wxshadow_page *page);
int wxshadow_restore_shadow_ranges(struct wxshadow_page *page);

/* ========== Page table functions (wxshadow_pgtable.c) ========== */

u64 *get_user_pte(void *mm, unsigned long addr, void **ptlp);
int wxshadow_try_split_pmd(void *mm, void *vma, unsigned long addr);
void pte_unmap_unlock(u64 *pte, void *ptl);
void wxshadow_flush_tlb_page(void *vma, unsigned long uaddr);
u64 make_pte(unsigned long pfn, u64 prot);
int wxshadow_page_activate_shadow(struct wxshadow_page *page, void *vma,
                                  unsigned long addr);
int wxshadow_page_activate_shadow_locked(struct wxshadow_page *page, void *vma,
                                         unsigned long addr);
int wxshadow_page_enter_original(struct wxshadow_page *page, void *vma,
                                 unsigned long addr);
int wxshadow_page_resume_shadow(struct wxshadow_page *page, void *vma,
                                unsigned long addr);
int wxshadow_page_begin_stepping(struct wxshadow_page *page, void *vma,
                                 unsigned long addr, void *task);
int wxshadow_page_finish_stepping(struct wxshadow_page *page, void *vma,
                                  unsigned long addr, void *task);
int wxshadow_page_restore_original_for_teardown_locked(
    struct wxshadow_page *page, void *vma, unsigned long addr);
int wxshadow_page_begin_gup_hide(struct wxshadow_page *page, void *mm,
                                 unsigned long addr, u64 **out_ptep,
                                 u64 *out_orig_pte);
int wxshadow_page_finish_gup_hide(struct wxshadow_page *page, void *vma,
                                  unsigned long addr, u64 *ptep,
                                  u64 orig_pte);
int wxshadow_page_restore_child_original_locked(struct wxshadow_page *page,
                                                void *child_mm,
                                                unsigned long addr);
int wxshadow_page_enter_dormant_locked(struct wxshadow_page *page, void *vma,
                                       unsigned long addr);

/* ========== Fork handler (wxshadow_handlers.c) ========== */

void before_dup_mmap_wx(hook_fargs2_t *args, void *udata);
void after_dup_mmap_wx(hook_fargs2_t *args, void *udata);
void before_uprobe_dup_mmap_wx(hook_fargs2_t *args, void *udata);
void after_uprobe_dup_mmap_wx(hook_fargs2_t *args, void *udata);
void before_copy_process_wx(hook_fargs8_t *args, void *udata);
void after_copy_process_wx(hook_fargs8_t *args, void *udata);

/* ========== Fault handler functions (wxshadow_handlers.c) ========== */

int wxshadow_handle_read_fault(void *mm, unsigned long addr);
int wxshadow_handle_exec_fault(void *mm, unsigned long addr);
void do_page_fault_before(hook_fargs3_t *args, void *udata);
void follow_page_pte_before(hook_fargs5_t *args, void *udata);
void follow_page_pte_after(hook_fargs5_t *args, void *udata);
void exit_mmap_before(hook_fargs1_t *args, void *udata);
int wxshadow_brk_handler(struct pt_regs *regs, unsigned int esr);
int wxshadow_step_handler(struct pt_regs *regs, unsigned int esr);
void brk_handler_before(hook_fargs3_t *args, void *udata);
void single_step_handler_before(hook_fargs3_t *args, void *udata);

/* ========== Breakpoint functions (wxshadow_bp.c) ========== */

int wxshadow_do_set_bp(void *mm, unsigned long addr);
int wxshadow_do_set_reg(void *mm, unsigned long addr, unsigned int reg_idx, unsigned long value);
int wxshadow_do_del_bp(void *mm, unsigned long addr);
int wxshadow_do_patch(void *mm, unsigned long addr, void __user *buf, unsigned long len);
int wxshadow_do_release(void *mm, unsigned long addr);
void prctl_before(hook_fargs4_t *args, void *udata);

/* ========== Scan functions (wxshadow_scan.c) ========== */

int resolve_symbols(void);
int scan_mm_struct_offsets(void);
int scan_vma_struct_offsets(void);
int detect_task_struct_offsets(void);
int try_scan_mm_context_id_offset(void);
void debug_print_tasks_list(int max_count);

#endif /* _KPM_WXSHADOW_INTERNAL_H_ */
