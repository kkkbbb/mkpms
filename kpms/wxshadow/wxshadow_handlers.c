/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * W^X Shadow Memory KPM Module - Exception Handlers
 *
 * BRK handler, Step handler, Page fault handlers, exit_mmap hook.
 *
 * Copyright (C) 2024
 */

#include "wxshadow_internal.h"

/* ========== Read/Exec Fault handlers ========== */

/*
 * Handle read fault - switch to original page with r-- permission
 * This allows integrity checks to see original code instead of BRK.
 * Returns 0 if handled, -1 if not our fault
 */
int wxshadow_handle_read_fault(void *mm, unsigned long addr)
{
    struct wxshadow_page *page_info;
    unsigned long page_addr = addr & PAGE_MASK;
    void *vma;
    int ret;

    page_info = wxshadow_find_page(mm, addr);  /* caller ref */
    if (!page_info)
        return -1;

    /* Get VMA for page switching (lockless) */
    vma = kfunc_find_vma(mm, addr);
    if (!vma || vma_start(vma) > addr) {
        wxshadow_teardown_page(page_info, "VMA Gone (read fault)");
        wxshadow_page_put(page_info);
        return -1;
    }

    /* Validate that mapping is still valid before switching */
    if (!wxshadow_validate_page_mapping(mm, vma, page_info, page_addr)) {
        wxshadow_teardown_page(page_info, "Mapping Changed (read fault)");
        wxshadow_page_put(page_info);
        return -1;
    }

    ret = wxshadow_page_enter_original(page_info, vma, page_addr);
    if (ret == 0)
        pr_info("wxshadow: read fault at %lx, switched to orig_backup (r--)\n", addr);

    wxshadow_page_put(page_info);  /* release caller ref */
    return ret == 0 ? 0 : -1;
}

/*
 * Handle exec fault - switch to shadow page with --x permission
 * Called when execution resumes after a read fault switched to original.
 * Returns 0 if handled, -1 if not our fault
 */
int wxshadow_handle_exec_fault(void *mm, unsigned long addr)
{
    struct wxshadow_page *page_info;
    unsigned long page_addr = addr & PAGE_MASK;
    void *shadow_kaddr;
    void *vma;
    int ret;

    page_info = wxshadow_find_page(mm, addr);  /* caller ref */
    if (!page_info)
        return -1;

    spin_lock(&global_lock);
    shadow_kaddr = page_info->shadow_page;
    spin_unlock(&global_lock);

    /* Get VMA for page switching (lockless) */
    vma = kfunc_find_vma(mm, addr);
    if (!vma || vma_start(vma) > addr) {
        wxshadow_teardown_page(page_info, "VMA Gone (exec fault)");
        wxshadow_page_put(page_info);
        return -1;
    }

    /* Validate that mapping is still valid before switching */
    if (!wxshadow_validate_page_mapping(mm, vma, page_info, page_addr)) {
        wxshadow_teardown_page(page_info, "Mapping Changed (exec fault)");
        wxshadow_page_put(page_info);
        return -1;
    }

    /* Clean dcache at kernel VA so shadow data is visible at PoU */
    if (shadow_kaddr)
        wxshadow_flush_kern_dcache_area((unsigned long)shadow_kaddr, PAGE_SIZE);

    ret = wxshadow_page_resume_shadow(page_info, vma, page_addr);
    if (ret == 0)
        pr_info("wxshadow: exec fault at %lx, switched to shadow (--x)\n", addr);

    wxshadow_page_put(page_info);  /* release caller ref */
    return ret == 0 ? 0 : -1;
}

/*
 * do_page_fault hook - intercept page faults for wxshadow pages
 * Signature: int do_page_fault(unsigned long far, unsigned int esr, struct pt_regs *regs)
 */
static void do_page_fault_before_impl(hook_fargs3_t *args, void *udata)
{
    unsigned long far = (unsigned long)args->arg0;
    unsigned int esr = (unsigned int)(unsigned long)args->arg1;
    void *mm;
    struct wxshadow_page *page;

    mm = kfunc_get_task_mm(current);
    if (!mm)
        return;

    /* Only handle permission faults, not translation faults */
    if (!is_permission_fault(esr)) {
        kfunc_mmput(mm);
        return;
    }

    /* Check if this is a wxshadow page at this address */
    page = wxshadow_find_page(mm, far);
    if (!page) {
        kfunc_mmput(mm);
        return;
    }

    if (is_el0_instruction_abort(esr)) {
        /* Instruction fetch fault - switch to shadow page */
        if (wxshadow_handle_exec_fault(mm, far) == 0) {
            args->ret = 0;
            args->skip_origin = true;
            wxshadow_page_put(page);   /* release our find_page ref */
            kfunc_mmput(mm);
            return;
        }
    } else if (!is_write_abort(esr)) {
        /* Read fault - switch to original page */
        if (wxshadow_handle_read_fault(mm, far) == 0) {
            args->ret = 0;
            args->skip_origin = true;
            wxshadow_page_put(page);   /* release our find_page ref */
            kfunc_mmput(mm);
            return;
        }
    } else {
        /* Write fault - auto cleanup */
        wxshadow_handle_write_fault(mm, far);
    }

    wxshadow_page_put(page);   /* release our find_page ref */
    kfunc_mmput(mm);
}

void do_page_fault_before(hook_fargs3_t *args, void *udata)
{
    WX_HANDLER_ENTER();
    do_page_fault_before_impl(args, udata);
    WX_HANDLER_EXIT();
}

/* ========== follow_page_pte hook (GUP hiding) ========== */

/*
 * Hook follow_page_pte to hide shadow pages from cross-process reads.
 *
 * /proc/pid/mem, process_vm_readv, ptrace all use GUP which calls
 * follow_page_pte to resolve a user PTE to a struct page.  This bypasses
 * user-space page faults entirely.
 *
 * Strategy: In the before hook, temporarily swap the PTE from shadow to
 * original so follow_page_pte reads the original PFN.  In the after hook,
 * swap it back.  We do NOT flush TLB, so the target process's execution
 * (which uses cached TLB entries pointing to shadow) is unaffected.
 *
 * follow_page_pte(vma, address, pmd, flags, pgmap)
 *   arg0 = vma, arg1 = address, arg2 = pmd, arg3 = flags, arg4 = pgmap
 *
 * We use arg5 (unused, hook_fargs5_t is hook_fargs8_t) to pass state
 * from before to after: arg5 = wxshadow_page ptr (with refcount held),
 * arg6 = original PTE value to restore.
 */

#define FOLL_WRITE 0x01

static void follow_page_pte_before_impl(hook_fargs5_t *args, void *udata)
{
    void *vma = (void *)args->arg0;
    unsigned long address = (unsigned long)args->arg1;
    unsigned int flags = (unsigned int)(unsigned long)args->arg3;
    void *mm;
    struct wxshadow_page *page;
    u64 *ptep;
    u64 orig_pte;

    args->arg5 = 0;  /* default: no restore needed */

    /* Fast path: no shadow pages at all */
    if (list_empty(&page_list))
        return;

    /* Only intercept reads */
    if (flags & FOLL_WRITE)
        return;

    mm = vma_mm(vma);
    if (!mm)
        return;

    page = wxshadow_find_page(mm, address);  /* takes ref */
    if (!page)
        return;

    if (wxshadow_page_begin_gup_hide(page, mm, page->page_addr, &ptep,
                                     &orig_pte) != 0) {
        wxshadow_page_put(page);
        return;
    }

    /* Pass state to after hook (page ref still held) */
    args->arg5 = (unsigned long)page;
    args->arg6 = orig_pte;
    args->arg7 = (unsigned long)ptep;
}

static void follow_page_pte_after_impl(hook_fargs5_t *args, void *udata)
{
    struct wxshadow_page *page = (void *)args->arg5;
    u64 orig_pte;
    u64 *ptep;
    void *vma;

    if (!page)
        return;

    orig_pte = (u64)args->arg6;
    ptep = (u64 *)args->arg7;
    vma = (void *)args->arg0;

    wxshadow_page_finish_gup_hide(page, vma, page->page_addr, ptep, orig_pte);
    wxshadow_page_put(page);  /* release ref from before hook */
}

void follow_page_pte_before(hook_fargs5_t *args, void *udata)
{
    WX_HANDLER_ENTER();
    follow_page_pte_before_impl(args, udata);
    WX_HANDLER_EXIT();
}

void follow_page_pte_after(hook_fargs5_t *args, void *udata)
{
    WX_HANDLER_ENTER();
    follow_page_pte_after_impl(args, udata);
    WX_HANDLER_EXIT();
}

/* ========== exit_mmap hook ========== */

/*
 * exit_mmap_before - called before exit_mmap runs zap_pte_range.
 *
 * Restores all shadow PTEs to original PTEs for this mm to prevent
 * "Bad page map" errors during exit_mmap's zap_pte_range pass.
 *
 * Uses an iterative pop-under-lock pattern (no fixed-size array) so it
 * handles any number of shadow pages.  Each iteration pops exactly one page:
 *   - Shadow pointer is captured and NULLed under lock → prevents double-free
 *     with the module exit loop.
 *   - Single-step is disabled for any task that was in STEPPING state.
 *   - PTE is restored to original before freeing the shadow page memory.
 *   - Page struct is released via wxshadow_page_put() (list's ref).
 */
static void exit_mmap_before_impl(hook_fargs1_t *args, void *udata)
{
    void *mm = (void *)args->arg0;
    int nr;

    if (!mm)
        return;

    nr = wxshadow_teardown_pages_for_mm(mm, "exit_mmap");
    if (nr > 0)
        pr_info("wxshadow: [exit_mmap] cleanup complete for mm=%px (%d pages)\n",
                mm, nr);
}

void exit_mmap_before(hook_fargs1_t *args, void *udata)
{
    WX_HANDLER_ENTER();
    exit_mmap_before_impl(args, udata);
    WX_HANDLER_EXIT();
}

/* ========== Fork protection handler ========== */

/*
 * Max shadow pages to fix per fork.  Stack array avoids allocation in
 * the after-copy_process callback (which runs with preemption disabled
 * on some kernels).
 */
#define FORK_FIX_BATCH  32

struct fork_fix_entry {
    struct wxshadow_page *page;
    unsigned long page_addr;
};

/*
 * wxshadow_fix_child_ptes - restore child's PTEs to original pages.
 *
 * After fork(), the child inherits the parent's page tables including any
 * shadow PTEs (--x pointing to shadow pages).  Since wxshadow only tracks
 * the parent's mm, the child would trigger unhandled BRKs or permission
 * faults.  This function walks the parent's shadow page list and rewrites
 * each corresponding PTE in the child's mm to point to the original page
 * with r-x permissions.
 */
static void wxshadow_fix_child_ptes(void *parent_mm, void *child_mm)
{
    struct fork_fix_entry batch[FORK_FIX_BATCH];
    int nr, i;
    struct list_head *pos;

    do {
        nr = 0;

        /* Collect a batch of pages under lock */
        spin_lock(&global_lock);
        list_for_each(pos, &page_list) {
            struct wxshadow_page *p =
                container_of(pos, struct wxshadow_page, list);
            if (p->mm == parent_mm && !p->dead && p->pfn_original) {
                p->refcount++;
                batch[nr].page = p;
                batch[nr].page_addr = p->page_addr;
                if (++nr >= FORK_FIX_BATCH)
                    break;
            }
        }
        spin_unlock(&global_lock);

        if (nr == 0)
            break;

        /* Fix each collected PTE in the child's mm (outside lock) */
        for (i = 0; i < nr; i++) {
            wxshadow_page_pte_lock(batch[i].page);
            wxshadow_page_restore_child_original_locked(batch[i].page, child_mm,
                                                        batch[i].page_addr);
            wxshadow_page_pte_unlock(batch[i].page);
            wxshadow_page_put(batch[i].page);
        }

        pr_info("wxshadow: [fork] fixed %d child PTEs (parent_mm=%px child_mm=%px)\n",
                nr, parent_mm, child_mm);

    } while (nr == FORK_FIX_BATCH);  /* Loop if batch was full (more pages) */
}

static void wxshadow_handle_fork(struct task_struct *new_task)
{
    void *parent_mm;
    void *child_mm = NULL;

    parent_mm = kfunc_get_task_mm(current);
    if (!parent_mm)
        return;

    if (task_struct_offset.mm_offset >= 0)
        safe_read_ptr((unsigned long)new_task + task_struct_offset.mm_offset, &child_mm);

    if (!child_mm || child_mm == parent_mm) {
        kfunc_mmput(parent_mm);
        return;
    }

    wxshadow_fix_child_ptes(parent_mm, child_mm);
    kfunc_mmput(parent_mm);
}

void after_copy_process_wx(hook_fargs8_t *args, void *udata)
{
    struct task_struct *new_task = (struct task_struct *)args->ret;

    WX_HANDLER_ENTER();
    if (new_task && !IS_ERR(new_task))
        wxshadow_handle_fork(new_task);
    WX_HANDLER_EXIT();
}

void after_cgroup_post_fork_wx(hook_fargs4_t *args, void *udata)
{
    WX_HANDLER_ENTER();
    if (args->arg0)
        wxshadow_handle_fork((struct task_struct *)args->arg0);
    WX_HANDLER_EXIT();
}

/* ========== BRK and Step handlers ========== */

/* Print register info */
static void wxshadow_print_regs(struct pt_regs *regs, unsigned long pc)
{
    pr_info("wxshadow: ======== Breakpoint Hit ========\n");
    pr_info("wxshadow: PC=%lx\n", pc);
    pr_info("wxshadow: x0=%016llx x1=%016llx x2=%016llx x3=%016llx\n",
            regs->regs[0], regs->regs[1], regs->regs[2], regs->regs[3]);
    pr_info("wxshadow: x4=%016llx x5=%016llx x6=%016llx x7=%016llx\n",
            regs->regs[4], regs->regs[5], regs->regs[6], regs->regs[7]);
    pr_info("wxshadow: x29(fp)=%016llx x30(lr)=%016llx\n",
            regs->regs[29], regs->regs[30]);
    pr_info("wxshadow: sp=%016llx pstate=%016llx\n",
            regs->sp, regs->pstate);
    pr_info("wxshadow: ================================\n");
}

/* Apply register modifications */
static void wxshadow_apply_reg_mods(struct pt_regs *regs, struct wxshadow_bp *bp)
{
    int i;
    for (i = 0; i < bp->nr_reg_mods; i++) {
        struct wxshadow_reg_mod *mod = &bp->reg_mods[i];
        if (!mod->enabled)
            continue;

        if (mod->reg_idx <= 30) {
            pr_info("wxshadow: modifying x%d: %016llx -> %016llx\n",
                    mod->reg_idx, regs->regs[mod->reg_idx], mod->value);
            regs->regs[mod->reg_idx] = mod->value;
        } else if (mod->reg_idx == 31) {
            pr_info("wxshadow: modifying sp: %016llx -> %016llx\n",
                    regs->sp, mod->value);
            regs->sp = mod->value;
        }
    }
}

/* Get current task's mm */
static void *get_current_mm(void)
{
    return kfunc_get_task_mm(current);
}

/*
 * Find page by virtual address - used in BRK handler.
 * If page is in STEPPING state, spin-wait for it to complete.
 *
 * Returns page_info with refcount incremented (caller must call
 * wxshadow_page_put when done).  Returns NULL if not found (no ref taken).
 */
static struct wxshadow_page *wxshadow_find_by_addr(void *mm, unsigned long addr)
{
    struct list_head *pos;
    struct wxshadow_page *page_info;
    unsigned long page_addr = addr & PAGE_MASK;
    int retry;

    spin_lock(&global_lock);
    list_for_each(pos, &page_list) {
        page_info = container_of(pos, struct wxshadow_page, list);

        if (page_info->mm != mm)
            continue;

        if (page_info->page_addr != page_addr)
            continue;

        if (!page_info->pfn_shadow)
            continue;

        if (page_info->state == WX_STATE_SHADOW_X) {
            page_info->refcount++;     /* caller's reference */
            spin_unlock(&global_lock);
            return page_info;
        }

        if (page_info->state == WX_STATE_STEPPING) {
            retry = 0;
            while (page_info->state == WX_STATE_STEPPING && retry++ < 10000) {
                spin_unlock(&global_lock);
                cpu_relax();
                spin_lock(&global_lock);
                if (list_empty(&page_list))
                    goto not_found;
            }

            if (page_info->state == WX_STATE_SHADOW_X) {
                pr_info("wxshadow: find_by_addr: waited %d iterations for STEPPING->SHADOW_X\n", retry);
                page_info->refcount++;  /* caller's reference */
                spin_unlock(&global_lock);
                return page_info;
            }

            pr_info("wxshadow: find_by_addr: timeout waiting for STEPPING, state=%d\n",
                    page_info->state);
            goto not_found;
        }

        pr_info("wxshadow: find_by_addr: found page but state=%d (need SHADOW_X=%d)\n",
                page_info->state, WX_STATE_SHADOW_X);
    }
not_found:
    spin_unlock(&global_lock);
    return NULL;
}

static bool wxshadow_can_resume_stale_brk(void *mm, unsigned long pc)
{
    u64 *ptep;
    u64 pte_val;
    unsigned long pfn;
    void *page_kaddr;
    u32 insn;

    ptep = get_user_pte(mm, pc, NULL);
    if (!ptep)
        return false;

    pte_val = *ptep;
    if (!(pte_val & PTE_VALID))
        return false;

    pfn = (pte_val & 0x0000FFFFFFFFF000UL) >> PAGE_SHIFT;
    page_kaddr = pfn_to_kaddr(pfn);
    if (!is_kva((unsigned long)page_kaddr))
        return false;

    insn = *(u32 *)((char *)page_kaddr + (pc & ~PAGE_MASK));
    return insn != WXSHADOW_BRK_INSN;
}

/* BRK handler implementation (called with in-flight counter already incremented) */
static int wxshadow_brk_handler_impl(struct pt_regs *regs, unsigned int esr)
{
    unsigned long pc = regs->pc;
    unsigned long page_addr = pc & PAGE_MASK;
    void *mm = get_current_mm();
    void *vma;
    struct wxshadow_page *page_info = NULL;
    struct wxshadow_bp *bp;
    int ret;

    pr_info("wxshadow: BRK handler ENTER pc=%lx esr=%x mm=%px\n", pc, esr, mm);

    if (!mm)
        return DBG_HOOK_ERROR;

    page_info = wxshadow_find_by_addr(mm, pc);  /* caller ref */
    if (!page_info) {
        if (wxshadow_can_resume_stale_brk(mm, pc)) {
            pr_info("wxshadow: BRK: stale trap at pc=%lx after release, resume current mapping\n",
                    pc);
            kfunc_mmput(mm);
            return DBG_HOOK_HANDLED;
        }
        pr_info("wxshadow: BRK: not our breakpoint at pc=%lx\n", pc);
        kfunc_mmput(mm);
        return DBG_HOOK_ERROR;
    }

    /*
     * If the page was marked dead by the exit loop between find_by_addr and
     * here, don't claim the BRK — let the kernel deliver SIGTRAP.  The exit
     * loop is already restoring the original PTE.
     */
    spin_lock(&global_lock);
    if (page_info->dead) {
        spin_unlock(&global_lock);
        wxshadow_page_put(page_info);
        kfunc_mmput(mm);
        return DBG_HOOK_ERROR;
    }
    spin_unlock(&global_lock);

    /* Get VMA (lockless) */
    vma = kfunc_find_vma(mm, pc);
    if (!vma || vma_start(vma) > pc) {
        wxshadow_teardown_page(page_info, "VMA Gone (BRK handler)");
        wxshadow_page_put(page_info);
        kfunc_mmput(mm);
        return DBG_HOOK_ERROR;
    }

    if (!wxshadow_validate_page_mapping(mm, vma, page_info, page_addr)) {
        wxshadow_teardown_page(page_info, "Mapping Changed (BRK handler)");
        wxshadow_page_put(page_info);
        kfunc_mmput(mm);
        return DBG_HOOK_ERROR;
    }

    bp = wxshadow_find_bp(page_info, pc);
    ret = wxshadow_page_begin_stepping(page_info, vma, page_addr, current);
    if (ret != 0) {
        wxshadow_page_put(page_info);
        kfunc_mmput(mm);
        if (ret == -16) {
            pr_info("wxshadow: BRK: page released while entering step at pc=%lx, resume on original mapping\n",
                    pc);
            return DBG_HOOK_HANDLED;
        }
        return DBG_HOOK_ERROR;
    }

    wxshadow_print_regs(regs, pc);

    if (bp && bp->nr_reg_mods > 0) {
        wxshadow_apply_reg_mods(regs, bp);
    }

    wxshadow_page_put(page_info);  /* release caller ref */
    kfunc_mmput(mm);

    kfunc_user_enable_single_step(current);

    pr_info("wxshadow: BRK handler EXIT success, single-step enabled\n");
    return DBG_HOOK_HANDLED;
}

int wxshadow_brk_handler(struct pt_regs *regs, unsigned int esr)
{
    int ret;
    WX_HANDLER_ENTER();
    ret = wxshadow_brk_handler_impl(regs, esr);
    WX_HANDLER_EXIT();
    return ret;
}

/* Single-step handler implementation */
static int wxshadow_step_handler_impl(struct pt_regs *regs, unsigned int esr)
{
    void *mm = get_current_mm();
    struct list_head *pos;
    struct wxshadow_page *page_info = NULL;
    void *vma;
    int found = 0;
    unsigned long page_addr = 0;
    int ret;

    if (!mm)
        return DBG_HOOK_ERROR;

    spin_lock(&global_lock);
    list_for_each(pos, &page_list) {
        page_info = container_of(pos, struct wxshadow_page, list);
        if (page_info->mm != mm)
            continue;

        if (page_info->state == WX_STATE_STEPPING &&
            page_info->stepping_task == current) {
            /*
             * If the exit loop marked this page dead between the BRK handler
             * setting STEPPING and us arriving here, skip the switch-to-shadow
             * (the exit loop is restoring the original mapping) and just
             * disable single-step.
             */
            if (page_info->dead) {
                spin_unlock(&global_lock);
                kfunc_user_disable_single_step(current);
                kfunc_mmput(mm);
                return DBG_HOOK_HANDLED;
            }
            page_addr = page_info->page_addr;
            page_info->refcount++;  /* caller's reference */
            found = 1;
            break;
        }
    }
    spin_unlock(&global_lock);

    if (!found) {
        pr_info("wxshadow: step handler: NOT FOUND! pc=%llx mm=%px current=%px\n",
                regs->pc, mm, current);
        spin_lock(&global_lock);
        list_for_each(pos, &page_list) {
            page_info = container_of(pos, struct wxshadow_page, list);
            pr_info("wxshadow:   page mm=%px addr=%lx: state=%d stepping_task=%px\n",
                    page_info->mm, page_info->page_addr, page_info->state, page_info->stepping_task);
        }
        spin_unlock(&global_lock);
        kfunc_mmput(mm);
        return DBG_HOOK_ERROR;
    }

    /* Get VMA (lockless) */
    vma = kfunc_find_vma(mm, page_addr);

    if (!vma || vma_start(vma) > page_addr) {
        wxshadow_teardown_page(page_info, "VMA Gone (step handler)");
        wxshadow_page_put(page_info);
        kfunc_mmput(mm);
        kfunc_user_disable_single_step(current);
        return DBG_HOOK_HANDLED;
    }

    if (!wxshadow_validate_page_mapping(mm, vma, page_info, page_addr)) {
        wxshadow_teardown_page(page_info, "Mapping Changed (step handler)");
        wxshadow_page_put(page_info);
        kfunc_mmput(mm);
        kfunc_user_disable_single_step(current);
        return DBG_HOOK_HANDLED;
    }

    ret = wxshadow_page_finish_stepping(page_info, vma, page_addr, current);
    if (ret < 0) {
        pr_err("wxshadow: step: failed to switch back to shadow for addr=%lx: %d\n",
               page_addr, ret);
        wxshadow_teardown_page(page_info, "step restore shadow failed");
        wxshadow_page_put(page_info);
        kfunc_mmput(mm);
        kfunc_user_disable_single_step(current);
        return DBG_HOOK_HANDLED;
    }

    if (ret > 0) {
        pr_info("wxshadow: step done at pc=%llx, finalized pending release\n",
                regs->pc);
    } else {
        pr_info("wxshadow: step done at pc=%llx, switched back to shadow\n",
                regs->pc);
        pr_info("wxshadow: step: state updated to SHADOW_X\n");
    }
    wxshadow_page_put(page_info);  /* release caller ref */
    kfunc_mmput(mm);

    kfunc_user_disable_single_step(current);

    return DBG_HOOK_HANDLED;
}

int wxshadow_step_handler(struct pt_regs *regs, unsigned int esr)
{
    int ret;
    WX_HANDLER_ENTER();
    ret = wxshadow_step_handler_impl(regs, esr);
    WX_HANDLER_EXIT();
    return ret;
}

/* ========== Direct handler hook wrappers (method 2) ========== */

#define BRK_COMMENT_MASK    0xFFFF
#define ESR_ELx_ISS_LOCAL(esr)    ((esr) & 0x1FFFFFF)

/*
 * brk_handler before hook
 */
void brk_handler_before(hook_fargs3_t *args, void *udata)
{
    unsigned int esr = (unsigned int)args->arg1;
    struct pt_regs *regs = (struct pt_regs *)args->arg2;
    u16 imm;
    int ret;

    imm = ESR_ELx_ISS_LOCAL(esr) & BRK_COMMENT_MASK;

    if (imm != WXSHADOW_BRK_IMM)
        return;

    if (!user_mode(regs))
        return;

    ret = wxshadow_brk_handler(regs, esr);
    if (ret == DBG_HOOK_HANDLED) {
        args->skip_origin = true;
        args->ret = 0;
    }
}

/*
 * single_step_handler before hook
 */
void single_step_handler_before(hook_fargs3_t *args, void *udata)
{
    unsigned int esr = (unsigned int)args->arg1;
    struct pt_regs *regs = (struct pt_regs *)args->arg2;
    int ret;

    if (!user_mode(regs))
        return;

    ret = wxshadow_step_handler(regs, esr);
    if (ret == DBG_HOOK_HANDLED) {
        args->skip_origin = true;
        args->ret = 0;
    }
}
