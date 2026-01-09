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
void (*kfunc_mmget)(void *mm);
/* find_task_by_vpid: use find_task_by_vpid() from linux/sched.h */

/* exit_mmap hook */
void *kfunc_exit_mmap = NULL;

/* Page allocation */
unsigned long (*kfunc___get_free_pages)(unsigned int gfp_mask, unsigned int order);
void (*kfunc_free_pages)(unsigned long addr, unsigned int order);
void (*kfunc_get_page)(void *page);
void (*kfunc_put_page)(void *page);

/* Address translation */
s64 *kvar_memstart_addr;
s64 *kvar_physvirt_offset;
unsigned long page_offset_base;
s64 detected_physvirt_offset;
int physvirt_offset_valid = 0;

/* GFP_KERNEL value */
unsigned int detected_gfp_kernel = 0;

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
void (*kfunc___sync_icache_dcache)(u64 pte);
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
void (*kfunc_unregister_user_break_hook)(struct wx_break_hook *hook);
void (*kfunc_register_user_step_hook)(struct wx_step_hook *hook);
void (*kfunc_unregister_user_step_hook)(struct wx_step_hook *hook);
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

/* rmap operations (optional) */
void (*kfunc_page_remove_rmap)(void *page, bool compound);
void (*kfunc_page_add_anon_rmap)(void *page, void *vma, unsigned long addr, bool compound);
void (*kfunc_page_add_new_anon_rmap)(void *page, void *vma, unsigned long addr, bool compound);
void (*kfunc_page_add_file_rmap)(void *page, bool compound);

/* do_page_fault hook */
void *kfunc_do_page_fault = NULL;

/* TLB flush */
void (*kfunc_flush_tlb_page)(void *vma, unsigned long uaddr);
void (*kfunc___flush_tlb_range)(void *vma, unsigned long start, unsigned long end,
                                 unsigned long stride, bool last_level, int tlb_level);

/* ========== mm_struct offsets ========== */

int16_t vma_vm_mm_offset = -1;
/* mm_pgd_offset: use mm_struct_offset.pgd_offset from KP framework */
int16_t mm_mmap_offset = 0x00;
/* NOTE: mm_page_table_lock_offset and mm_mmap_lock_offset_dyn removed (lockless) */

/* mm->context.id offset for ASID (detected at runtime, -1 = not detected) */
int16_t mm_context_id_offset = -1;

/* TLB flush mode (default: auto) */
int tlb_flush_mode = WX_TLB_MODE_BROADCAST;

/* ========== Global state ========== */

/* Use KP framework's list_head and spinlock_t */
LIST_HEAD(page_list);           /* Global list of wxshadow_page */
DEFINE_SPINLOCK(global_lock);

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

/* ========== Helper functions ========== */

/*
 * Find page by mm and address
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
    INIT_LIST_HEAD(&page->list);

    spin_lock(&global_lock);
    list_add(&page->list, &page_list);
    spin_unlock(&global_lock);

    pr_info("wxshadow: created page for mm=%px addr=%lx\n", mm, page_addr);
    return page;
}

/*
 * Free a page structure and remove from list
 */
void wxshadow_free_page(struct wxshadow_page *page)
{
    unsigned long shadow_vaddr = 0;

    if (!page)
        return;

    spin_lock(&global_lock);
    list_del_init(&page->list);
    if (page->shadow_page)
        shadow_vaddr = (unsigned long)page->shadow_page;
    spin_unlock(&global_lock);

    if (shadow_vaddr)
        kfunc_free_pages(shadow_vaddr, 0);

    kfunc_kfree(page);
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

    pr_info("wxshadow: validate_mapping: PFN mismatch for addr %lx: "
            "current=%lx, orig=%lx, shadow=%lx, state=%d\n",
            page_addr, current_pfn, page_info->pfn_original,
            page_info->pfn_shadow, page_info->state);
    return 0;
}

int wxshadow_auto_cleanup_page(struct wxshadow_page *page, const char *reason)
{
    unsigned long shadow_vaddr = 0;
    int i;

    if (!page)
        return -1;

    pr_info("wxshadow: ===============================================\n");
    pr_info("wxshadow: === AUTO CLEANUP: %s ===\n", reason);
    pr_info("wxshadow: ===============================================\n");
    pr_info("wxshadow:   Page addr:  0x%lx\n", page->page_addr);
    pr_info("wxshadow:   State:      %d\n", page->state);
    pr_info("wxshadow:   PFN orig:   0x%lx\n", page->pfn_original);
    pr_info("wxshadow:   PFN shadow: 0x%lx\n", page->pfn_shadow);

    spin_lock(&global_lock);
    for (i = 0; i < page->nr_bps; i++) {
        if (page->bps[i].active) {
            pr_info("wxshadow:   Removing BP at 0x%lx\n", page->bps[i].addr);
            page->bps[i].active = false;
            memset(&page->bps[i].reg_mods, 0, sizeof(page->bps[i].reg_mods));
            page->bps[i].nr_reg_mods = 0;
        }
    }

    if (page->stepping_task) {
        pr_info("wxshadow:   Clearing stepping task %px\n", page->stepping_task);
        page->stepping_task = NULL;
    }

    if (page->shadow_page)
        shadow_vaddr = (unsigned long)page->shadow_page;

    /* Remove page from list */
    list_del_init(&page->list);
    spin_unlock(&global_lock);

    if (shadow_vaddr) {
        kfunc_free_pages(shadow_vaddr, 0);
        pr_info("wxshadow:   Freed shadow page\n");
    }

    kfunc_kfree(page);

    pr_info("wxshadow: ===============================================\n");
    return 0;
}

int wxshadow_handle_write_fault(void *mm, unsigned long addr)
{
    struct wxshadow_page *page;

    page = wxshadow_find_page(mm, addr);
    if (!page || page->state == WX_STATE_NONE)
        return -1;

    pr_info("wxshadow: write fault at %lx - page content changing\n", addr);

    wxshadow_auto_cleanup_page(page, "Write Fault (page modified)");

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
            /* Manual unregister, skip synchronize_rcu (hangs in KPM context) */
            if (kptr_debug_hook_lock)
                spin_lock(kptr_debug_hook_lock);
            list_del_rcu(&wxshadow_step_hook.node);
            list_del_rcu(&wxshadow_break_hook.node);
            if (kptr_debug_hook_lock)
                spin_unlock(kptr_debug_hook_lock);
            INIT_LIST_HEAD(&wxshadow_step_hook.node);
            INIT_LIST_HEAD(&wxshadow_break_hook.node);
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

    pr_info("wxshadow: W^X shadow memory module loaded\n");
    pr_info("wxshadow: use prctl(0x%x, pid, addr) to set breakpoint\n", PR_WXSHADOW_SET_BP);
    pr_info("wxshadow: use prctl(0x%x, pid, addr, reg, val) to set reg mod\n", PR_WXSHADOW_SET_REG);
    pr_info("wxshadow: use prctl(0x%x, pid, addr) to delete breakpoint\n", PR_WXSHADOW_DEL_BP);
    if (kfunc_do_page_fault) {
        pr_info("wxshadow: read hiding ENABLED (do_page_fault hooked)\n");
    } else {
        pr_info("wxshadow: read hiding DISABLED\n");
    }

    /* Debug: print first 10 processes */
    debug_print_tasks_list(10);

    return 0;
}

/*
 * wxshadow_cleanup_page - fully cleanup a page (restore mapping, free resources)
 * Called during module unload. Must be called WITHOUT global_lock held.
 */
static void wxshadow_cleanup_page(struct wxshadow_page *page)
{
    void *mm = page->mm;
    void *vma = NULL;

    pr_info("wxshadow: cleanup page addr=%lx state=%d stepping_task=%px\n",
            page->page_addr, page->state, page->stepping_task);

    /* Disable single step if task is stepping */
    if (page->stepping_task && kfunc_user_disable_single_step) {
        pr_info("wxshadow: disabling single step for task %px\n", page->stepping_task);
        kfunc_user_disable_single_step(page->stepping_task);
        page->stepping_task = NULL;
    }

    /* Try to get VMA for restoring page table mappings */
    if (mm && kfunc_find_vma) {
        vma = kfunc_find_vma(mm, page->page_addr);
        if (vma && vma_start(vma) > page->page_addr)
            vma = NULL;
    }

    /* Restore original page mapping if possible */
    if (vma && page->pfn_original &&
        (page->state == WX_STATE_SHADOW_X || page->state == WX_STATE_STEPPING)) {
        /* Restore to original page with r-x permission */
        u64 prot = PTE_USER | PTE_RDONLY;  /* r-x */
        int ret = wxshadow_switch_mapping(vma, page->page_addr, page->pfn_original, prot);
        if (ret == 0) {
            pr_info("wxshadow: restored original mapping for addr=%lx pfn=%lx\n",
                    page->page_addr, page->pfn_original);
            wxshadow_flush_icache_page(page->page_addr);
        } else {
            pr_warn("wxshadow: failed to restore mapping for addr=%lx\n", page->page_addr);
        }
    }

    /* Free shadow page */
    if (page->shadow_page) {
        kfunc_free_pages((unsigned long)page->shadow_page, 0);
        pr_info("wxshadow: freed shadow page for addr=%lx\n", page->page_addr);
    }

    kfunc_kfree(page);
}

static long wxshadow_exit(void *__user reserved)
{
    struct list_head *pos, *n;
    struct wxshadow_page *page;
    struct wxshadow_page **pages_to_free = NULL;
    int page_count = 0;
    int i;

    pr_info("wxshadow: unloading...\n");

    /* Unhook do_page_fault first */
    if (kfunc_do_page_fault) {
        hook_unwrap(kfunc_do_page_fault, do_page_fault_before, NULL);
        pr_info("wxshadow: unhooked do_page_fault\n");
    }

    /* Unhook exit_mmap */
    if (kfunc_exit_mmap) {
        hook_unwrap(kfunc_exit_mmap, exit_mmap_before, NULL);
        pr_info("wxshadow: unhooked exit_mmap\n");
    }

    /* Unhook prctl */
    unhook_syscalln(__NR_prctl, prctl_before, NULL);

    /* Unregister BRK/step handlers based on hook method */
    if (hook_method == WX_HOOK_METHOD_DIRECT) {
        hook_unwrap(kfunc_single_step_handler, single_step_handler_before, NULL);
        hook_unwrap(kfunc_brk_handler, brk_handler_before, NULL);
        pr_info("wxshadow: unhooked brk_handler and single_step_handler (direct)\n");
    } else if (hook_method == WX_HOOK_METHOD_REGISTER) {
        /*
         * Manual unregister: the kernel's unregister_user_*_hook calls
         * synchronize_rcu() which hangs in KPM exit context.
         *
         * We manually:
         * 1. Hold debug_hook_lock (if available)
         * 2. list_del_rcu both hooks
         * 3. Release lock
         * 4. Call synchronize_rcu (if available) to wait for readers
         */
        pr_info("wxshadow: unregistering hooks (manual)...\n");

        if (kptr_debug_hook_lock) {
            spin_lock(kptr_debug_hook_lock);
        } else {
            pr_warn("wxshadow: debug_hook_lock not found, unsafe unregister\n");
        }

        list_del_rcu(&wxshadow_step_hook.node);
        list_del_rcu(&wxshadow_break_hook.node);

        if (kptr_debug_hook_lock) {
            spin_unlock(kptr_debug_hook_lock);
        }

        /* Re-init list_head to safe state */
        INIT_LIST_HEAD(&wxshadow_step_hook.node);
        INIT_LIST_HEAD(&wxshadow_break_hook.node);

        /*
         * NOTE: We intentionally skip synchronize_rcu() here.
         * It hangs in KPM exit context (likely due to the calling context).
         *
         * This is acceptable because:
         * 1. The hook functions are in KPM .text, valid until unload completes
         * 2. Debug hook RCU readers (step/brk handlers) are very short-lived
         * 3. We've already removed nodes from the list under debug_hook_lock
         *
         * Worst case: a concurrent handler sees stale data briefly, but
         * the function pointers remain valid throughout this exit sequence.
         */
        pr_info("wxshadow: skipping synchronize_rcu (hangs in KPM exit context)\n");

        pr_info("wxshadow: unregistered break/step hooks (register API)\n");
    }
    hook_method = WX_HOOK_METHOD_NONE;

    /* Count pages first */
    spin_lock(&global_lock);
    list_for_each(pos, &page_list) {
        page_count++;
    }

    if (page_count > 0) {
        /* Allocate array to hold page pointers */
        spin_unlock(&global_lock);
        pages_to_free = kfunc_kzalloc(page_count * sizeof(struct wxshadow_page *),
                                      detected_gfp_kernel);
        spin_lock(&global_lock);

        if (pages_to_free) {
            /* Collect all pages and remove from list */
            i = 0;
            list_for_each_safe(pos, n, &page_list) {
                page = container_of(pos, struct wxshadow_page, list);
                list_del_init(&page->list);
                if (i < page_count) {
                    pages_to_free[i++] = page;
                }
            }
            page_count = i;  /* Actual count collected */
        } else {
            /* Fallback: just remove from list without proper cleanup */
            pr_warn("wxshadow: failed to allocate cleanup array, leaking memory\n");
            list_for_each_safe(pos, n, &page_list) {
                page = container_of(pos, struct wxshadow_page, list);
                list_del_init(&page->list);
            }
            page_count = 0;
        }
    }
    spin_unlock(&global_lock);

    /* Cleanup pages outside the lock */
    for (i = 0; i < page_count; i++) {
        if (pages_to_free[i]) {
            wxshadow_cleanup_page(pages_to_free[i]);
        }
    }

    if (pages_to_free) {
        kfunc_kfree(pages_to_free);
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
