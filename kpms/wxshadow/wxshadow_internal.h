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
/* init_task: use wx_init_task via kallsyms (framework doesn't export it) */
#include <pgtable.h>
#include <asm/current.h>
#include <syscall.h>
#include <kputils.h>
#include <asm/ptrace.h>

#include "wxshadow.h"

/* ========== ARM64 CPU helpers ========== */

static inline void cpu_relax(void)
{
    asm volatile("yield" ::: "memory");
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

#define wx_for_each_process(p) \
    for (p = wx_init_task; (p = wx_next_task(p)) != wx_init_task; )

/* ========== Kernel function pointers ========== */

/* Memory management */
extern void *(*kfunc_find_vma)(void *mm, unsigned long addr);
extern void *(*kfunc_get_task_mm)(void *task);
extern void (*kfunc_mmput)(void *mm);
extern void (*kfunc_mmget)(void *mm);
/* find_task_by_vpid: use find_task_by_vpid() from linux/sched.h */

/* exit_mmap hook */
extern void *kfunc_exit_mmap;

/* Page allocation */
extern unsigned long (*kfunc___get_free_pages)(unsigned int gfp_mask, unsigned int order);
extern void (*kfunc_free_pages)(unsigned long addr, unsigned int order);
extern void (*kfunc_get_page)(void *page);
extern void (*kfunc_put_page)(void *page);

/* Address translation */
extern s64 *kvar_memstart_addr;
extern s64 *kvar_physvirt_offset;
extern unsigned long page_offset_base;
extern s64 detected_physvirt_offset;
extern int physvirt_offset_valid;

/* GFP_KERNEL value */
extern unsigned int detected_gfp_kernel;

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
/* NOTE: wxfunc_lookup_name is deprecated - use lookup_name_safe() directly in wxshadow_scan.c
 * kallsyms_lookup_name() can hang when traversing module symbols on some kernels */
#define wxfunc_lookup_name(func) wx_##func = (typeof(wx_##func))kallsyms_lookup_name(#func)

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
extern void (*kfunc___sync_icache_dcache)(u64 pte);
extern void (*kfunc_flush_dcache_page)(void *page);
extern void (*kfunc___flush_icache_range)(unsigned long start, unsigned long end);

/* Debug/ptrace */
extern void (*kfunc_user_enable_single_step)(void *task);
extern void (*kfunc_user_disable_single_step)(void *task);

/* Direct handler hook */
extern void *kfunc_brk_handler;
extern void *kfunc_single_step_handler;

/* Locking - NOT USED (lockless operation) */

/* RCU */
extern void (*kfunc_rcu_read_lock)(void);
extern void (*kfunc_rcu_read_unlock)(void);

/* Memory allocation */
extern void *(*kfunc_kzalloc)(size_t size, unsigned int flags);
extern void *(*kfunc_kcalloc)(size_t n, size_t size, unsigned int flags);
extern void (*kfunc_kfree)(void *ptr);

/* Safe memory access */
extern long (*kfunc_copy_from_kernel_nofault)(void *dst, const void *src, size_t size);

/* rmap operations (optional) */
extern void (*kfunc_page_remove_rmap)(void *page, bool compound);
extern void (*kfunc_page_add_anon_rmap)(void *page, void *vma, unsigned long addr, bool compound);
extern void (*kfunc_page_add_new_anon_rmap)(void *page, void *vma, unsigned long addr, bool compound);
extern void (*kfunc_page_add_file_rmap)(void *page, bool compound);

/* do_page_fault hook */
extern void *kfunc_do_page_fault;

/* TLB flush */
extern void (*kfunc_flush_tlb_page)(void *vma, unsigned long uaddr);
extern void (*kfunc___flush_tlb_range)(void *vma, unsigned long start, unsigned long end,
                                        unsigned long stride, bool last_level, int tlb_level);

/* ========== mm_struct offsets ========== */

extern int16_t vma_vm_mm_offset;
/* mm_pgd_offset: use mm_struct_offset.pgd_offset from KP framework (linux/mm_types.h) */
extern int16_t mm_mmap_offset;
/* NOTE: mm_page_table_lock_offset and mm_mmap_lock_offset_dyn are NOT used (lockless) */

/* mm->context.id offset for ASID (detected at runtime) */
extern int16_t mm_context_id_offset;

/* TLB flush mode control */
extern int tlb_flush_mode;

/* ========== Global state ========== */

/* Use KP framework's spinlock_t and list_head from linux/spinlock.h and linux/list.h */
extern struct list_head page_list;      /* Global list of wxshadow_page */
extern spinlock_t global_lock;

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

static inline bool is_write_abort(unsigned int esr)
{
    return (esr & ESR_ELx_WNR) != 0;
}

static inline bool is_permission_fault(unsigned int esr)
{
    unsigned int fsc = esr & 0x3F;
    return (fsc & 0x3C) == 0x0C;
}

/*
 * Use KP framework's spinlock and list from linux/spinlock.h and linux/list.h:
 * - spin_lock() / spin_unlock()
 * - INIT_LIST_HEAD() / list_add() / list_del_init() / list_empty()
 * - list_for_each() / list_for_each_safe()
 * - container_of() from linux/container_of.h
 */

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

static inline void wxshadow_flush_icache_range(unsigned long start, unsigned long end)
{
    if (kfunc___flush_icache_range) {
        kfunc___flush_icache_range(start, end);
        asm volatile("isb" : : : "memory");
        return;
    }
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

struct wxshadow_page *wxshadow_find_page(void *mm, unsigned long addr);
struct wxshadow_page *wxshadow_create_page(void *mm, unsigned long page_addr);
void wxshadow_free_page(struct wxshadow_page *page);
struct wxshadow_bp *wxshadow_find_bp(struct wxshadow_page *page_info, unsigned long addr);
int wxshadow_validate_page_mapping(void *mm, void *vma, struct wxshadow_page *page_info, unsigned long page_addr);
int wxshadow_auto_cleanup_page(struct wxshadow_page *page, const char *reason);
int wxshadow_handle_write_fault(void *mm, unsigned long addr);

/* ========== Page table functions (wxshadow_pgtable.c) ========== */

u64 *get_user_pte(void *mm, unsigned long addr, void **ptlp);
void pte_unmap_unlock(u64 *pte, void *ptl);
void wxshadow_set_pte_at(void *mm, unsigned long addr, u64 *ptep, u64 pte);
void wxshadow_flush_tlb_page(void *vma, unsigned long uaddr);
u64 make_pte(unsigned long pfn, u64 prot);
int wxshadow_switch_mapping(void *vma, unsigned long addr, unsigned long target_pfn, u64 prot);

/* ========== Fault handler functions (wxshadow_handlers.c) ========== */

int wxshadow_handle_read_fault(void *mm, unsigned long addr);
int wxshadow_handle_exec_fault(void *mm, unsigned long addr);
void do_page_fault_before(hook_fargs3_t *args, void *udata);
void exit_mmap_before(hook_fargs1_t *args, void *udata);
int wxshadow_brk_handler(struct pt_regs *regs, unsigned int esr);
int wxshadow_step_handler(struct pt_regs *regs, unsigned int esr);
void brk_handler_before(hook_fargs3_t *args, void *udata);
void single_step_handler_before(hook_fargs3_t *args, void *udata);

/* ========== Breakpoint functions (wxshadow_bp.c) ========== */

int wxshadow_do_set_bp(void *mm, unsigned long addr);
int wxshadow_do_set_reg(void *mm, unsigned long addr, unsigned int reg_idx, unsigned long value);
int wxshadow_do_del_bp(void *mm, unsigned long addr);
void prctl_before(hook_fargs4_t *args, void *udata);

/* ========== Scan functions (wxshadow_scan.c) ========== */

int resolve_symbols(void);
int scan_mm_struct_offsets(void);
int scan_vma_struct_offsets(void);
int detect_task_struct_offsets(void);
int try_scan_mm_context_id_offset(void);
void debug_print_tasks_list(int max_count);

#endif /* _KPM_WXSHADOW_INTERNAL_H_ */
