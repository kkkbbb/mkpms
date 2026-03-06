/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * W^X Shadow Memory KPM Module - Main
 *
 * Provides shadow page mechanism for hook hiding. When a breakpoint is set
 * via prctl, a shadow page is created with BRK instruction. Read access
 * returns original content while execution hits the breakpoint.
 *
 * Copyright (C) 2024
 */

#include "wxshadow_internal.h"

/* prctl syscall number */
#ifndef __NR_prctl
#define __NR_prctl 167
#endif

KPM_NAME("wxshadow");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("wxshadow");
KPM_DESCRIPTION("W^X Shadow Memory - Hidden Breakpoint Mechanism");

/* ========== Global variable definitions ========== */

/*
 * task_struct_offset: use extern from linux/sched.h (KernelPatch framework)
 * init_task: use extern from linux/init_task.h (KernelPatch framework)
 */

/* ========== Kernel function pointers ========== */

/* Memory management */
void *(*kfunc_find_vma)(void *mm, unsigned long addr);
void *(*kfunc_get_task_mm)(void *task);
void (*kfunc_mmput)(void *mm);
/* find_task_by_vpid: use find_task_by_vpid() from linux/sched.h */

/* exit_mmap hook */
void *kfunc_exit_mmap = NULL;

/* Page allocation */
unsigned long (*kfunc___get_free_pages)(unsigned int gfp_mask, unsigned int order);
void (*kfunc_free_pages)(unsigned long addr, unsigned int order);

/* Address translation */
s64 *kvar_memstart_addr;
s64 *kvar_physvirt_offset;
unsigned long page_offset_base;
s64 detected_physvirt_offset;
int physvirt_offset_valid = 0;

/* Page table config */
int wx_page_shift;
int wx_page_level;

/* Spinlock functions - using wxfunc_def macro */
void wxfunc_def(_raw_spin_lock)(raw_spinlock_t *lock) = 0;
void wxfunc_def(_raw_spin_unlock)(raw_spinlock_t *lock) = 0;

/* Task functions - using wxfunc_def macro */
struct task_struct *wxfunc_def(find_task_by_vpid)(pid_t nr) = 0;
pid_t wxfunc_def(__task_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;

/* init_task - looked up via kallsyms since framework doesn't export it */
struct task_struct *wx_init_task = 0;

/* Cache operations */
void (*kfunc_flush_dcache_page)(void *page);
void (*kfunc___flush_icache_range)(unsigned long start, unsigned long end);

/* Debug/ptrace */
void (*kfunc_user_enable_single_step)(void *task);
void (*kfunc_user_disable_single_step)(void *task);

/* Direct handler hook */
void *kfunc_brk_handler;
void *kfunc_single_step_handler;

/* register_user_*_hook API (fallback) */
void (*kfunc_register_user_break_hook)(struct wx_break_hook *hook);
void (*kfunc_register_user_step_hook)(struct wx_step_hook *hook);
spinlock_t *kptr_debug_hook_lock;  /* kernel's debug_hook_lock for safe unregister */

/* Locking - NOT USED (lockless operation) */

/* RCU */
void (*kfunc_rcu_read_lock)(void);
void (*kfunc_rcu_read_unlock)(void);
void (*kfunc_synchronize_rcu)(void);

/* Memory allocation */
void *(*kfunc_kzalloc)(size_t size, unsigned int flags);
void *(*kfunc_kcalloc)(size_t n, size_t size, unsigned int flags);
void (*kfunc_kfree)(void *ptr);

/* Safe memory access */
long (*kfunc_copy_from_kernel_nofault)(void *dst, const void *src, size_t size);

/* do_page_fault hook */
void *kfunc_do_page_fault = NULL;

/* follow_page_pte hook (GUP hiding for /proc/pid/mem etc.) */
void *kfunc_follow_page_pte = NULL;

/* copy_process hook (fork protection) */
void *kfunc_copy_process = NULL;
void *kfunc_cgroup_post_fork = NULL;

/* TLB flush */
void (*kfunc_flush_tlb_page)(void *vma, unsigned long uaddr);
void (*kfunc___flush_tlb_range)(void *vma, unsigned long start, unsigned long end,
                                 unsigned long stride, bool last_level, int tlb_level);

/* THP split */
void (*kfunc___split_huge_pmd)(void *vma, void *pmd, unsigned long address,
                                bool freeze, void *page);

/* ========== mm_struct offsets ========== */

int16_t vma_vm_mm_offset = -1;
/* mm_pgd_offset: use mm_struct_offset.pgd_offset from KP framework */
/* NOTE: mm_page_table_lock_offset and mm_mmap_lock_offset_dyn removed (lockless) */

/* mm->context.id offset for ASID (detected at runtime, -1 = not detected) */
int16_t mm_context_id_offset = -1;

/* TLB flush mode (default: auto) */
int tlb_flush_mode = WX_TLB_MODE_PRECISE;

/* ========== Global state ========== */

/* Use KP framework's list_head and spinlock_t */
LIST_HEAD(page_list);           /* Global list of wxshadow_page */
DEFINE_SPINLOCK(global_lock);

/*
 * In-flight handler counter — see wxshadow_internal.h for rationale.
 * KP calls kp_free_exec() immediately after exit() returns, so we must
 * ensure no module code is executing before we return from exit().
 */
atomic_t wx_in_flight = ATOMIC_INIT(0);

/* ========== BRK/Step hook structures ========== */

/* Current hook method */
enum wx_hook_method hook_method = WX_HOOK_METHOD_NONE;

/* Forward declaration for hook callbacks */
static int wxshadow_brk_hook_fn(struct pt_regs *regs, unsigned int esr);
static int wxshadow_step_hook_fn(struct pt_regs *regs, unsigned int esr);

/* Hook instances for register_user_*_hook API */
static struct wx_break_hook wxshadow_break_hook = {
    .fn = wxshadow_brk_hook_fn,
    .imm = WXSHADOW_BRK_IMM,
    .mask = 0,
};

static struct wx_step_hook wxshadow_step_hook = {
    .fn = wxshadow_step_hook_fn,
};

/* NOTE: mmap lock wrappers removed - lockless operation */

/* ========== Reference counting helpers ========== */

/*
 * wxshadow_page_put - release one reference.
 * kfree's the struct when refcount reaches zero.
 * Acquires global_lock internally; safe from any context.
 */
void wxshadow_page_put(struct wxshadow_page *page)
{
    int should_free;

    spin_lock(&global_lock);
    should_free = (--page->refcount == 0);
    spin_unlock(&global_lock);

    if (should_free)
        kfunc_kfree(page);
}

/* ========== Helper functions ========== */

/*
 * Find page by mm and address.
 * Returns page with refcount incremented (caller must wxshadow_page_put).
 * Returns NULL if not found (no ref taken).
 */
struct wxshadow_page *wxshadow_find_page(void *mm, unsigned long addr)
{
    struct list_head *pos;
    struct wxshadow_page *page;
    unsigned long target_addr = addr & PAGE_MASK;

    spin_lock(&global_lock);
    list_for_each(pos, &page_list) {
        page = container_of(pos, struct wxshadow_page, list);
        if (page->mm == mm && page->page_addr == target_addr) {
            page->refcount++;          /* caller's reference */
            spin_unlock(&global_lock);
            return page;
        }
    }
    spin_unlock(&global_lock);
    return NULL;
}

/*
 * Create a new page structure
 */
struct wxshadow_page *wxshadow_create_page(void *mm, unsigned long page_addr)
{
    struct wxshadow_page *page;

    /* Allocate new page structure */
    page = kfunc_kzalloc(sizeof(*page), 0xcc0);
    if (!page)
        return NULL;

    page->mm = mm;
    page->page_addr = page_addr;
    page->state = WX_STATE_NONE;
    page->refcount = 1;            /* list's reference */
    page->dead = false;
    INIT_LIST_HEAD(&page->list);

    spin_lock(&global_lock);
    list_add(&page->list, &page_list);
    spin_unlock(&global_lock);

    pr_info("wxshadow: created page for mm=%px addr=%lx\n", mm, page_addr);
    return page;
}

/*
 * Free a page structure and remove from list.
 * Must be called only when no external caller ref exists (refcount == 1,
 * i.e. only the list's ref).  Used in error paths after wxshadow_create_page.
 */
void wxshadow_free_page(struct wxshadow_page *page)
{
    unsigned long shadow_vaddr = 0;
    unsigned long backup_vaddr = 0;

    if (!page)
        return;

    /* Capture shadow/backup pointers and mark dead under lock to prevent double-free
     * races with exit_mmap_before or the exit loop. */
    spin_lock(&global_lock);
    page->dead = true;
    list_del_init(&page->list);
    if (page->shadow_page) {
        shadow_vaddr = (unsigned long)page->shadow_page;
        page->shadow_page = NULL;
    }
    if (page->orig_backup) {
        backup_vaddr = (unsigned long)page->orig_backup;
        page->orig_backup = NULL;
    }
    spin_unlock(&global_lock);

    if (shadow_vaddr)
        kfunc_free_pages(shadow_vaddr, 0);
    if (backup_vaddr)
        kfunc_free_pages(backup_vaddr, 0);

    /* Release the list's ref (refcount was 1 → 0 → kfree). */
    wxshadow_page_put(page);
}

struct wxshadow_bp *wxshadow_find_bp(struct wxshadow_page *page_info, unsigned long pc)
{
    int i;
    for (i = 0; i < page_info->nr_bps; i++) {
        if (page_info->bps[i].active && page_info->bps[i].addr == pc)
            return &page_info->bps[i];
    }
    return NULL;
}

int wxshadow_validate_page_mapping(void *mm, void *vma,
                                   struct wxshadow_page *page_info,
                                   unsigned long page_addr)
{
    u64 *ptep;
    u64 pte_val;
    unsigned long current_pfn;

    if (!vma || vma_start(vma) > page_addr || vma_end(vma) <= page_addr) {
        pr_info("wxshadow: validate_mapping: VMA invalid for addr %lx\n", page_addr);
        return 0;
    }

    ptep = get_user_pte(mm, page_addr, NULL);
    if (!ptep) {
        pr_info("wxshadow: validate_mapping: PTE not found for addr %lx\n", page_addr);
        return 0;
    }

    pte_val = *ptep;
    if (!(pte_val & PTE_VALID)) {
        pr_info("wxshadow: validate_mapping: PTE invalid for addr %lx\n", page_addr);
        return 0;
    }

    current_pfn = (pte_val & 0x0000FFFFFFFFF000UL) >> PAGE_SHIFT;

    if (page_info->pfn_shadow && current_pfn == page_info->pfn_shadow)
        return 1;

    if (page_info->pfn_original && current_pfn == page_info->pfn_original) {
        if (page_info->state == WX_STATE_ORIGINAL ||
            page_info->state == WX_STATE_STEPPING ||
            page_info->state == WX_STATE_SHADOW_X) {
            return 1;
        }
    }

    if (page_info->pfn_orig_backup && current_pfn == page_info->pfn_orig_backup) {
        if (page_info->state == WX_STATE_ORIGINAL ||
            page_info->state == WX_STATE_STEPPING) {
            return 1;
        }
    }

    pr_info("wxshadow: validate_mapping: PFN mismatch for addr %lx: "
            "current=%lx, orig=%lx, shadow=%lx, state=%d\n",
            page_addr, current_pfn, page_info->pfn_original,
            page_info->pfn_shadow, page_info->state);
    return 0;
}

/*
 * wxshadow_teardown_page - unified page cleanup.
 *
 * Performs a complete, safe teardown of a shadow page:
 *   1. Under global_lock: mark dead, capture and NULL shadow_page/orig_backup/
 *      stepping_task, remove from page_list (if still present).
 *   2. Disable single-step on the stepping task (with pointer validation).
 *   3. Brief spin for any concurrent step-handler that already passed the
 *      dead check (covers the STEPPING race window).
 *   4. Restore PTE to original page (if mm and VMA are still valid).
 *   5. Flush icache.
 *   6. Free shadow and backup page memory.
 *   7. Release the list's reference via wxshadow_page_put().
 *
 * Caller MUST hold a ref (from find_page / find_by_addr) and must call
 * wxshadow_page_put() after this function returns.
 *
 * Safe to call even if the page has already been removed from page_list
 * (list_del_init is idempotent on an initialized-but-empty node).
 */
void wxshadow_teardown_page(struct wxshadow_page *page, const char *reason)
{
    unsigned long shadow_vaddr = 0;
    unsigned long backup_vaddr = 0;
    void *stepping = NULL;
    int state;
    bool was_in_list;

    if (!page)
        return;

    /* --- Step 1: mark dead, capture resources, remove from list --- */
    spin_lock(&global_lock);
    page->dead = true;
    state = page->state;

    stepping = page->stepping_task;
    page->stepping_task = NULL;

    if (page->shadow_page) {
        shadow_vaddr = (unsigned long)page->shadow_page;
        page->shadow_page = NULL;
    }
    if (page->orig_backup) {
        backup_vaddr = (unsigned long)page->orig_backup;
        page->orig_backup = NULL;
    }

    was_in_list = !list_empty(&page->list);
    if (was_in_list)
        list_del_init(&page->list);
    spin_unlock(&global_lock);

    pr_info("wxshadow: [teardown] %s: addr=%lx state=%d\n",
            reason, page->page_addr, state);

    /* --- Step 2: disable single-step with validation --- */
    if (stepping && kfunc_user_disable_single_step) {
        u64 probe;
        if (is_kva((unsigned long)stepping) &&
            safe_read_u64((unsigned long)stepping, &probe)) {
            kfunc_user_disable_single_step(stepping);
        } else {
            pr_warn("wxshadow: [teardown] stepping_task %px stale, skip disable\n",
                    stepping);
        }
    }

    /* --- Step 3: spin for concurrent step-handler (STEPPING race) --- */
    if (state == WX_STATE_STEPPING) {
        int w;
        for (w = 0; w < 50000; w++)
            cpu_relax();
    }

    /* --- Step 4: restore PTE to original --- */
    if (page->mm && page->pfn_original && kfunc_find_vma) {
        void *mm = page->mm;
        u64 probe;
        if (is_kva((unsigned long)mm) &&
            safe_read_u64((unsigned long)mm, &probe)) {
            void *vma = kfunc_find_vma(mm, page->page_addr);
            if (vma && vma_start(vma) <= page->page_addr) {
                u64 prot = PTE_USER | PTE_RDONLY;  /* r-x */
                if (wxshadow_switch_mapping(vma, page->page_addr,
                                            page->pfn_original, prot) == 0) {
                    wxshadow_flush_icache_page(page->page_addr);
                }
            }
        }
    }

    /* --- Step 5: free shadow and backup page memory --- */
    if (shadow_vaddr)
        kfunc_free_pages(shadow_vaddr, 0);
    if (backup_vaddr)
        kfunc_free_pages(backup_vaddr, 0);

    /* --- Step 6: release list's reference --- */
    if (was_in_list)
        wxshadow_page_put(page);
}

int wxshadow_handle_write_fault(void *mm, unsigned long addr)
{
    struct wxshadow_page *page;

    page = wxshadow_find_page(mm, addr);  /* caller ref */
    if (!page)
        return -1;

    if (page->state == WX_STATE_NONE) {
        wxshadow_page_put(page);
        return -1;
    }

    pr_info("wxshadow: write fault at %lx - page content changing\n", addr);

    wxshadow_teardown_page(page, "Write Fault (page modified)");
    wxshadow_page_put(page);

    return -1;
}

/* ========== Hook callback functions for register_user_*_hook API ========== */

/*
 * BRK hook callback for register_user_break_hook
 * Called by kernel's brk_handler when our BRK imm matches.
 * Note: Unlike direct hook, we don't need to check imm here - kernel already matched it.
 */
static int wxshadow_brk_hook_fn(struct pt_regs *regs, unsigned int esr)
{
    return wxshadow_brk_handler(regs, esr);
}

/*
 * Step hook callback for register_user_step_hook
 * Called by kernel's single_step_handler for user-mode single-step exceptions.
 */
static int wxshadow_step_hook_fn(struct pt_regs *regs, unsigned int esr)
{
    return wxshadow_step_handler(regs, esr);
}

/* ========== Unload helpers ========== */

/*
 * wx_unregister_brk_step_hooks - remove break/step hooks from kernel's
 * debug hook lists under debug_hook_lock.  Safe to call from both the
 * init failure path and wxshadow_exit().
 * NOTE: caller must NOT call synchronize_rcu() — KP holds rcu_read_lock
 * while invoking module exit, which would deadlock.
 */
static void wx_unregister_brk_step_hooks(void)
{
    if (kptr_debug_hook_lock) {
        spin_lock(kptr_debug_hook_lock);
    } else {
        pr_warn("wxshadow: debug_hook_lock not found, unsafe unregister\n");
    }
    list_del_rcu(&wxshadow_step_hook.node);
    list_del_rcu(&wxshadow_break_hook.node);
    if (kptr_debug_hook_lock)
        spin_unlock(kptr_debug_hook_lock);
    INIT_LIST_HEAD(&wxshadow_step_hook.node);
    INIT_LIST_HEAD(&wxshadow_break_hook.node);
}

/* ========== Module init/exit ========== */

static long wxshadow_init(const char *args, const char *event, void *__user reserved)
{
    int ret;

    pr_info("wxshadow: initializing...\n");

    /* Resolve kernel symbols */
    ret = resolve_symbols();
    if (ret < 0) {
        pr_err("wxshadow: failed to resolve symbols\n");
        return ret;
    }

    /* Scan mm_struct offsets */
    ret = scan_mm_struct_offsets();
    if (ret < 0) {
        pr_err("wxshadow: failed to scan mm_struct offsets\n");
        return ret;
    }

    /* Scan vm_area_struct offsets */
    ret = scan_vma_struct_offsets();
    if (ret < 0) {
        pr_err("wxshadow: failed to scan vma offsets\n");
        return ret;
    }

    /* Detect task_struct offsets */
    ret = detect_task_struct_offsets();
    if (ret < 0) {
        pr_err("wxshadow: failed to detect task_struct offsets\n");
        return ret;
    }

    /* Only scan mm->context.id if we need TLBI instruction fallback */
    if (!kfunc_flush_tlb_page && !kfunc___flush_tlb_range) {
        pr_info("wxshadow: no kernel TLB flush function, need mm->context.id for TLBI\n");
        ret = try_scan_mm_context_id_offset();
        if (ret < 0) {
            /* Scan may fail if in kernel thread context (ASID=0 in TTBR0).
             * Will retry lazily at first prctl call when in user process context. */
            pr_info("wxshadow: context.id scan deferred (will retry at first prctl)\n");
        }
    }

    /* page_list already initialized by LIST_HEAD() macro */

    /* Register BRK/step handlers */
    /* NOTE: Temporarily prefer REGISTER method for testing */
    if (kfunc_register_user_break_hook && kfunc_register_user_step_hook) {
        /* Method 1: register_user_*_hook API (testing priority) */
        pr_info("wxshadow: using register_user_*_hook API (testing priority)\n");

        /* Initialize list_head nodes */
        INIT_LIST_HEAD(&wxshadow_break_hook.node);
        INIT_LIST_HEAD(&wxshadow_step_hook.node);

        pr_info("wxshadow: registering break hook (imm=0x%x)...\n", wxshadow_break_hook.imm);
        kfunc_register_user_break_hook(&wxshadow_break_hook);
        pr_info("wxshadow: registered break hook\n");

        pr_info("wxshadow: registering step hook...\n");
        kfunc_register_user_step_hook(&wxshadow_step_hook);
        pr_info("wxshadow: registered step hook\n");

        hook_method = WX_HOOK_METHOD_REGISTER;
    } else if (kfunc_brk_handler && kfunc_single_step_handler) {
        /* Method 2: Direct hook (fallback) */
        pr_info("wxshadow: using direct hook method (fallback)\n");

        pr_info("wxshadow: hooking brk_handler at %px...\n", kfunc_brk_handler);
        ret = hook_wrap3(kfunc_brk_handler, brk_handler_before, NULL, NULL);
        if (ret != HOOK_NO_ERR) {
            pr_err("wxshadow: failed to hook brk_handler: %d\n", ret);
            return -1;
        }
        pr_info("wxshadow: hooked brk_handler\n");

        pr_info("wxshadow: hooking single_step_handler at %px...\n", kfunc_single_step_handler);
        ret = hook_wrap3(kfunc_single_step_handler, single_step_handler_before, NULL, NULL);
        if (ret != HOOK_NO_ERR) {
            pr_err("wxshadow: failed to hook single_step_handler: %d\n", ret);
            hook_unwrap(kfunc_brk_handler, brk_handler_before, NULL);
            return -1;
        }
        pr_info("wxshadow: hooked single_step_handler\n");

        hook_method = WX_HOOK_METHOD_DIRECT;
    } else {
        pr_err("wxshadow: no hook method available\n");
        return -1;
    }

    /* Hook prctl syscall */
    ret = hook_syscalln(__NR_prctl, 5, prctl_before, NULL, NULL);
    if (ret != HOOK_NO_ERR) {
        pr_err("wxshadow: failed to hook prctl: %d\n", ret);
        /* Cleanup based on hook method */
        if (hook_method == WX_HOOK_METHOD_DIRECT) {
            hook_unwrap(kfunc_single_step_handler, single_step_handler_before, NULL);
            hook_unwrap(kfunc_brk_handler, brk_handler_before, NULL);
        } else if (hook_method == WX_HOOK_METHOD_REGISTER) {
            wx_unregister_brk_step_hooks();
        }
        hook_method = WX_HOOK_METHOD_NONE;
        return -1;
    }
    pr_info("wxshadow: hooked prctl syscall\n");

    /* Hook do_page_fault for read/exec fault handling */
    if (kfunc_do_page_fault) {
        ret = hook_wrap3(kfunc_do_page_fault, do_page_fault_before, NULL, NULL);
        if (ret != HOOK_NO_ERR) {
            pr_warn("wxshadow: failed to hook do_page_fault: %d\n", ret);
            pr_warn("wxshadow: read hiding will be disabled\n");
            kfunc_do_page_fault = NULL;
        } else {
            pr_info("wxshadow: hooked do_page_fault for read/exec fault handling\n");
        }
    }

    /* Hook exit_mmap */
    if (kfunc_exit_mmap) {
        ret = hook_wrap1(kfunc_exit_mmap, exit_mmap_before, NULL, NULL);
        if (ret != HOOK_NO_ERR) {
            pr_warn("wxshadow: failed to hook exit_mmap: %d\n", ret);
            pr_warn("wxshadow: process exit may cause Bad page map errors\n");
            kfunc_exit_mmap = NULL;
        } else {
            pr_info("wxshadow: hooked exit_mmap for proper cleanup\n");
        }
    }

    /* Hook follow_page_pte for GUP hiding (/proc/pid/mem, process_vm_readv, ptrace) */
    if (kfunc_follow_page_pte) {
        ret = hook_wrap5(kfunc_follow_page_pte,
                         follow_page_pte_before, follow_page_pte_after, NULL);
        if (ret != HOOK_NO_ERR) {
            pr_warn("wxshadow: failed to hook follow_page_pte: %d\n", ret);
            kfunc_follow_page_pte = NULL;
        } else {
            pr_info("wxshadow: hooked follow_page_pte for GUP hiding\n");
        }
    }

    /* Hook copy_process for fork protection (optional) */
    if (patch_config) {
        unsigned long cp_addr = patch_config->copy_process;
        unsigned long cpf_addr = patch_config->cgroup_post_fork;
        if (cp_addr) {
            kfunc_copy_process = (void *)cp_addr;
            ret = hook_wrap8(kfunc_copy_process, NULL, after_copy_process_wx, NULL);
            if (ret != HOOK_NO_ERR) {
                pr_warn("wxshadow: failed to hook copy_process: %d\n", ret);
                kfunc_copy_process = NULL;
            } else {
                pr_info("wxshadow: hooked copy_process at %px for fork protection\n",
                        kfunc_copy_process);
            }
        }
        if (!kfunc_copy_process && cpf_addr) {
            kfunc_cgroup_post_fork = (void *)cpf_addr;
            ret = hook_wrap4(kfunc_cgroup_post_fork, NULL, after_cgroup_post_fork_wx, NULL);
            if (ret != HOOK_NO_ERR) {
                pr_warn("wxshadow: failed to hook cgroup_post_fork: %d\n", ret);
                kfunc_cgroup_post_fork = NULL;
            } else {
                pr_info("wxshadow: hooked cgroup_post_fork at %px for fork protection\n",
                        kfunc_cgroup_post_fork);
            }
        }
        if (!kfunc_copy_process && !kfunc_cgroup_post_fork) {
            pr_warn("wxshadow: fork protection DISABLED (no copy_process/cgroup_post_fork)\n");
        }
    } else {
        pr_warn("wxshadow: patch_config not available, fork protection DISABLED\n");
    }

    pr_info("wxshadow: W^X shadow memory module loaded\n");
    pr_info("wxshadow: use prctl(0x%x, pid, addr) to set breakpoint\n", PR_WXSHADOW_SET_BP);
    pr_info("wxshadow: use prctl(0x%x, pid, addr, reg, val) to set reg mod\n", PR_WXSHADOW_SET_REG);
    pr_info("wxshadow: use prctl(0x%x, pid, addr) to delete breakpoint\n", PR_WXSHADOW_DEL_BP);
    pr_info("wxshadow: use prctl(0x%x, pid, addr, buf, len) to patch shadow\n", PR_WXSHADOW_PATCH);
    pr_info("wxshadow: use prctl(0x%x, pid, addr) to release shadow\n", PR_WXSHADOW_RELEASE);
    if (kfunc_do_page_fault) {
        pr_info("wxshadow: read hiding ENABLED (do_page_fault hooked)\n");
    } else {
        pr_info("wxshadow: read hiding DISABLED\n");
    }
    if (kfunc_follow_page_pte) {
        pr_info("wxshadow: GUP hiding ENABLED (follow_page_pte hooked)\n");
    } else {
        pr_info("wxshadow: GUP hiding DISABLED\n");
    }

    /* Debug: print first 10 processes */
    debug_print_tasks_list(10);

    return 0;
}

/*
 * wait_for_handlers_drain - spin until all in-flight handlers complete.
 *
 * Called after unhooking each set of handlers.  Because KP calls
 * kp_free_exec(mod->start) immediately after exit() returns, we MUST
 * ensure no module code is executing before we return.
 *
 * Steps:
 *  1. Short busy-wait (200 K iterations, ~200 µs): covers the narrow window
 *     between a CPU obtaining the fn pointer from the hook list (via
 *     rcu_dereference) and calling WX_HANDLER_ENTER().  ARM64 BRK/step
 *     handlers run with IRQs disabled, so this window is < 10 CPU cycles;
 *     200 K cpu_relax cycles is more than sufficient.
 *  2. Wait for wx_in_flight counter to reach 0: ensures any handler that
 *     already incremented the counter has fully decremented it (i.e. has
 *     returned from the module function).
 *  3. Up to ~1 s timeout with a warning if something is stuck.
 */
static void wait_for_handlers_drain(const char *phase)
{
    int i, iters = 0;

    /* Step 1: cover the "fn obtained but not yet entered handler" window */
    for (i = 0; i < 200000; i++)
        cpu_relax();

    /* Step 2: wait for all active handlers to finish */
    while (atomic_read(&wx_in_flight) > 0) {
        cpu_relax();
        if (++iters > 10000000) {
            pr_warn("wxshadow: [%s] timeout waiting for in-flight handlers "
                    "(in_flight=%d)\n", phase, atomic_read(&wx_in_flight));
            break;
        }
    }

    if (iters > 0)
        pr_info("wxshadow: [%s] drained in-flight handlers (%d iters)\n",
                phase, iters);
}

static long wxshadow_exit(void *__user reserved)
{
    struct wxshadow_page *page;
    int page_count = 0;

    pr_info("wxshadow: unloading...\n");

    /*
     * Phase 1: Unhook prctl to block new user operations.
     * BRK/step/fault/exit_mmap hooks remain active throughout Phase 2
     * to handle any in-flight operations while pages are being cleaned.
     */
    unhook_syscalln(__NR_prctl, prctl_before, NULL);
    pr_info("wxshadow: unhooked prctl (phase 1)\n");

    /*
     * Phase 2: Iteratively pop and clean every page from page_list.
     * exit_mmap_before is still active to handle concurrent process exits;
     * it will compete with this loop via global_lock — whoever calls
     * list_del_init first owns the page.
     * BRK/step handlers are still active and will find no page once
     * it has been popped here.
     */
    while (1) {
        spin_lock(&global_lock);
        if (list_empty(&page_list)) {
            spin_unlock(&global_lock);
            break;
        }
        page = list_first_entry(&page_list, struct wxshadow_page, list);
        page->refcount++;  /* caller ref for teardown */
        spin_unlock(&global_lock);

        wxshadow_teardown_page(page, "module unload");
        wxshadow_page_put(page);  /* release caller ref */
        page_count++;
    }
    pr_info("wxshadow: cleaned %d pages (phase 2)\n", page_count);

    /*
     * Phase 2.5: Unhook fork protection (copy_process / cgroup_post_fork).
     * Must be done before BRK/step unhook — fork handler may reference
     * shadow pages, but page_list is already empty so it will be a no-op.
     */
    if (kfunc_copy_process) {
        hook_unwrap(kfunc_copy_process, NULL, after_copy_process_wx);
        pr_info("wxshadow: unhooked copy_process (phase 2.5)\n");
        wait_for_handlers_drain("phase2.5-copy_process");
    }
    if (kfunc_cgroup_post_fork) {
        hook_unwrap(kfunc_cgroup_post_fork, NULL, after_cgroup_post_fork_wx);
        pr_info("wxshadow: unhooked cgroup_post_fork (phase 2.5)\n");
        wait_for_handlers_drain("phase2.5-cgroup_post_fork");
    }

    /*
     * Phase 3: Unhook BRK and step handlers.
     * page_list is now empty, so any handler that starts after Phase 2
     * will find no matching page and return quickly.  However handlers
     * that STARTED before Phase 2 completed (and are still executing
     * module code) must finish before kp_free_exec() is called.
     * wait_for_handlers_drain() handles this via the wx_in_flight counter.
     */
    if (hook_method == WX_HOOK_METHOD_DIRECT) {
        hook_unwrap(kfunc_single_step_handler, single_step_handler_before, NULL);
        hook_unwrap(kfunc_brk_handler, brk_handler_before, NULL);
        pr_info("wxshadow: unhooked brk/step handlers (direct, phase 3)\n");

        /* Wait for any in-flight direct-hook handler to complete */
        wait_for_handlers_drain("phase3-direct");

    } else if (hook_method == WX_HOOK_METHOD_REGISTER) {
        /*
         * Manual unregister via list_del_rcu under debug_hook_lock.
         * Cannot call synchronize_rcu() — KP's unload_module() holds
         * rcu_read_lock() while calling our exit, so synchronize_rcu()
         * would deadlock.
         */
        pr_info("wxshadow: unregistering hooks (manual, phase 3)...\n");
        wx_unregister_brk_step_hooks();
        wait_for_handlers_drain("phase3-register");
        pr_info("wxshadow: unregistered break/step hooks (register API, phase 3)\n");
    }
    hook_method = WX_HOOK_METHOD_NONE;

    /*
     * Phase 4: Unhook do_page_fault.
     * page_list is empty; fault handler will find no pages to process.
     */
    if (kfunc_do_page_fault) {
        hook_unwrap(kfunc_do_page_fault, do_page_fault_before, NULL);
        pr_info("wxshadow: unhooked do_page_fault (phase 4)\n");
        wait_for_handlers_drain("phase4-fault");
    }

    /*
     * Phase 4.5: Unhook access_remote_vm.
     * page_list is empty; handler will find no overlapping pages.
     */
    if (kfunc_follow_page_pte) {
        hook_unwrap(kfunc_follow_page_pte, follow_page_pte_before,
                    follow_page_pte_after);
        pr_info("wxshadow: unhooked follow_page_pte (phase 4.5)\n");
        wait_for_handlers_drain("phase4.5-follow_page_pte");
    }

    /*
     * Phase 5: Unhook exit_mmap last.
     * It was guarding Phase 2 against concurrent process exits.
     * Safe to remove now that page_list is empty.
     */
    if (kfunc_exit_mmap) {
        hook_unwrap(kfunc_exit_mmap, exit_mmap_before, NULL);
        pr_info("wxshadow: unhooked exit_mmap (phase 5)\n");
        wait_for_handlers_drain("phase5-exit_mmap");
    }

    pr_info("wxshadow: module unloaded (cleaned %d pages)\n", page_count);
    return 0;
}

static long wxshadow_control(const char *args, char *__user out_msg, int outlen)
{
    pr_info("wxshadow: control called with args: %s\n", args ? args : "(null)");
    return 0;
}

KPM_INIT(wxshadow_init);
KPM_CTL0(wxshadow_control);
KPM_EXIT(wxshadow_exit);
