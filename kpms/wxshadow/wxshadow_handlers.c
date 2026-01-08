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
    u64 prot;
    int ret;

    page_info = wxshadow_find_page(mm, addr);
    if (!page_info)
        return -1;

    spin_lock(&global_lock);

    /* Only switch if currently on shadow with --x permission */
    if (page_info->state != WX_STATE_SHADOW_X) {
        spin_unlock(&global_lock);
        return -1;
    }

    /* Must have original page reference */
    if (!page_info->pfn_original) {
        spin_unlock(&global_lock);
        return -1;
    }
    spin_unlock(&global_lock);

    /* Get VMA for page switching (lockless) */
    vma = kfunc_find_vma(mm, addr);
    if (!vma || vma_start(vma) > addr) {
        pr_info("wxshadow: read_fault: VMA gone for addr=%lx, auto cleanup\n", addr);
        wxshadow_auto_cleanup_page(page_info, "VMA Gone (read fault)");
        return -1;
    }

    /* Validate that mapping is still valid before switching */
    if (!wxshadow_validate_page_mapping(mm, vma, page_info, page_addr)) {
        pr_info("wxshadow: read_fault: mapping invalid for addr=%lx, auto cleanup\n", addr);
        wxshadow_auto_cleanup_page(page_info, "Mapping Changed (read fault)");
        return -1;
    }

    /* Switch to original page with r-- permission (readable, no exec) */
    prot = PTE_USER | PTE_RDONLY | PTE_UXN;

    ret = wxshadow_switch_mapping(vma, page_addr, page_info->pfn_original, prot);

    if (ret == 0) {
        spin_lock(&global_lock);
        page_info->state = WX_STATE_ORIGINAL;
        spin_unlock(&global_lock);
        pr_info("wxshadow: read fault at %lx, switched to original (r--)\n", addr);
    }

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
    void *vma;
    u64 prot;
    int ret;

    page_info = wxshadow_find_page(mm, addr);
    if (!page_info)
        return -1;

    spin_lock(&global_lock);

    /* Must have shadow page */
    if (!page_info->pfn_shadow) {
        spin_unlock(&global_lock);
        return -1;
    }

    /* If already on shadow or stepping, nothing to do */
    if (page_info->state == WX_STATE_SHADOW_X ||
        page_info->state == WX_STATE_STEPPING) {
        spin_unlock(&global_lock);
        return -1;
    }

    /* Should be in ORIGINAL state after a read fault */
    if (page_info->state != WX_STATE_ORIGINAL) {
        spin_unlock(&global_lock);
        return -1;
    }
    spin_unlock(&global_lock);

    /* Get VMA for page switching (lockless) */
    vma = kfunc_find_vma(mm, addr);
    if (!vma || vma_start(vma) > addr) {
        pr_info("wxshadow: exec_fault: VMA gone for addr=%lx, auto cleanup\n", addr);
        wxshadow_auto_cleanup_page(page_info, "VMA Gone (exec fault)");
        return -1;
    }

    /* Validate that mapping is still valid before switching */
    if (!wxshadow_validate_page_mapping(mm, vma, page_info, page_addr)) {
        pr_info("wxshadow: exec_fault: mapping invalid for addr=%lx, auto cleanup\n", addr);
        wxshadow_auto_cleanup_page(page_info, "Mapping Changed (exec fault)");
        return -1;
    }

    /* Flush dcache before making executable */
    if (kfunc_flush_dcache_page && page_info->shadow_page)
        kfunc_flush_dcache_page(page_info->shadow_page);

    /* Switch to shadow page with --x permission (exec only, no read) */
    prot = 0;

    ret = wxshadow_switch_mapping(vma, page_addr, page_info->pfn_shadow, prot);

    if (ret == 0) {
        wxshadow_flush_icache_page(page_addr);

        spin_lock(&global_lock);
        page_info->state = WX_STATE_SHADOW_X;
        spin_unlock(&global_lock);
        pr_info("wxshadow: exec fault at %lx, switched to shadow (--x)\n", addr);
    }

    return ret == 0 ? 0 : -1;
}

/*
 * do_page_fault hook - intercept page faults for wxshadow pages
 * Signature: int do_page_fault(unsigned long far, unsigned int esr, struct pt_regs *regs)
 */
void do_page_fault_before(hook_fargs3_t *args, void *udata)
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
            kfunc_mmput(mm);
            return;
        }
    } else if (!is_write_abort(esr)) {
        /* Read fault - switch to original page */
        if (wxshadow_handle_read_fault(mm, far) == 0) {
            args->ret = 0;
            args->skip_origin = true;
            kfunc_mmput(mm);
            return;
        }
    } else {
        /* Write fault - auto cleanup */
        wxshadow_handle_write_fault(mm, far);
    }

    kfunc_mmput(mm);
}

/* ========== exit_mmap hook ========== */

/*
 * exit_mmap_before - called before exit_mmap runs zap_pte_range
 * Restore all shadow PTEs to original PTEs to avoid "Bad page map" errors.
 */
void exit_mmap_before(hook_fargs1_t *args, void *udata)
{
    void *mm = (void *)args->arg0;
    struct list_head *pos, *n;
    struct wxshadow_page *page_info;
    struct wxshadow_page *pages_to_cleanup[64];
    int nr_pages = 0;
    int i;

    if (!mm)
        return;

    /* First pass: find all pages for this mm under global_lock */
    spin_lock(&global_lock);
    list_for_each_safe(pos, n, &page_list) {
        page_info = container_of(pos, struct wxshadow_page, list);
        if (page_info->mm == mm) {
            if (nr_pages < 64) {
                pages_to_cleanup[nr_pages++] = page_info;
                list_del_init(&page_info->list);
            }
        }
    }
    spin_unlock(&global_lock);

    if (nr_pages == 0)
        return;

    pr_info("wxshadow: [exit_mmap] mm=%px, restoring %d pages\n", mm, nr_pages);

    /* Second pass: restore PTEs and free shadow pages */
    for (i = 0; i < nr_pages; i++) {
        unsigned long shadow_vaddr;
        void *vma;
        void *ptl = NULL;
        u64 *pte;
        u64 entry;

        page_info = pages_to_cleanup[i];

        if (!page_info->pfn_shadow || !page_info->pfn_original) {
            kfunc_kfree(page_info);
            continue;
        }

        shadow_vaddr = (unsigned long)page_info->shadow_page;

        vma = kfunc_find_vma(mm, page_info->page_addr);
        if (!vma || page_info->page_addr < vma_start(vma)) {
            pr_info("wxshadow: [exit_mmap] VMA gone for %lx, freeing shadow\n", page_info->page_addr);
            if (shadow_vaddr)
                kfunc_free_pages(shadow_vaddr, 0);
            kfunc_kfree(page_info);
            continue;
        }

        pte = get_user_pte(mm, page_info->page_addr, &ptl);
        if (pte && (*pte & PTE_VALID)) {
            entry = (page_info->pfn_original << PAGE_SHIFT) |
                    PTE_VALID | PTE_TYPE_PAGE | PTE_AF | PTE_SHARED |
                    PTE_NG | PTE_ATTRINDX_NORMAL | PTE_USER | PTE_RDONLY;

            pr_info("wxshadow: [exit_mmap] restoring PTE at %lx: %llx -> %llx\n",
                    page_info->page_addr, *pte, entry);

            wxshadow_set_pte_at(mm, page_info->page_addr, pte, entry);
            pte_unmap_unlock(pte, ptl);

            wxshadow_flush_tlb_page(vma, page_info->page_addr);
        } else {
            if (pte)
                pte_unmap_unlock(pte, ptl);
        }

        if (shadow_vaddr) {
            pr_info("wxshadow: [exit_mmap] freeing shadow page at %lx\n", shadow_vaddr);
            kfunc_free_pages(shadow_vaddr, 0);
        }

        kfunc_kfree(page_info);
    }

    pr_info("wxshadow: [exit_mmap] cleanup complete for mm=%px\n", mm);
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
 * Returns page_info pointer if found and in SHADOW_X state.
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

/* BRK handler */
int wxshadow_brk_handler(struct pt_regs *regs, unsigned int esr)
{
    unsigned long pc = regs->pc;
    unsigned long page_addr = pc & PAGE_MASK;
    void *mm = get_current_mm();
    void *vma;
    struct wxshadow_page *page_info = NULL;
    struct wxshadow_bp *bp;
    u64 prot;

    pr_info("wxshadow: BRK handler ENTER pc=%lx esr=%x mm=%px\n", pc, esr, mm);

    if (!mm)
        return DBG_HOOK_ERROR;

    page_info = wxshadow_find_by_addr(mm, pc);
    if (!page_info) {
        pr_info("wxshadow: BRK: not our breakpoint at pc=%lx\n", pc);
        kfunc_mmput(mm);
        return DBG_HOOK_ERROR;
    }

    /* Get VMA (lockless) */
    vma = kfunc_find_vma(mm, pc);
    if (!vma || vma_start(vma) > pc) {
        pr_info("wxshadow: BRK handler: VMA not found for pc=%lx, auto cleanup\n", pc);
        wxshadow_auto_cleanup_page(page_info, "VMA Gone (process exit?)");
        kfunc_mmput(mm);
        return DBG_HOOK_ERROR;
    }

    if (!wxshadow_validate_page_mapping(mm, vma, page_info, page_addr)) {
        pr_info("wxshadow: BRK handler: mapping invalid for pc=%lx, auto cleanup\n", pc);
        wxshadow_auto_cleanup_page(page_info, "Mapping Changed (COW/remap?)");
        kfunc_mmput(mm);
        return DBG_HOOK_ERROR;
    }

    wxshadow_print_regs(regs, pc);

    bp = wxshadow_find_bp(page_info, pc);
    if (bp && bp->nr_reg_mods > 0) {
        wxshadow_apply_reg_mods(regs, bp);
    }

    prot = PTE_USER | PTE_RDONLY;

    pr_info("wxshadow: BRK switching to original: orig_pfn=%lx shadow_pfn=%lx\n",
            page_info->pfn_original, page_info->pfn_shadow);

    if (wxshadow_switch_mapping(vma, page_addr, page_info->pfn_original, prot) != 0) {
        kfunc_mmput(mm);
        regs->pc += AARCH64_INSN_SIZE;
        return DBG_HOOK_HANDLED;
    }

    wxshadow_flush_icache_page(page_addr);

    spin_lock(&global_lock);
    page_info->state = WX_STATE_STEPPING;
    page_info->stepping_task = current;
    spin_unlock(&global_lock);

    kfunc_mmput(mm);

    kfunc_user_enable_single_step(current);

    pr_info("wxshadow: BRK handler EXIT success, single-step enabled\n");
    return DBG_HOOK_HANDLED;
}

/* Single-step handler */
int wxshadow_step_handler(struct pt_regs *regs, unsigned int esr)
{
    void *mm = get_current_mm();
    struct list_head *pos;
    struct wxshadow_page *page_info = NULL;
    void *vma;
    int found = 0;
    u64 prot;
    unsigned long page_addr = 0;
    unsigned long pfn_shadow = 0;

    if (!mm)
        return DBG_HOOK_ERROR;

    spin_lock(&global_lock);
    list_for_each(pos, &page_list) {
        page_info = container_of(pos, struct wxshadow_page, list);
        if (page_info->mm != mm)
            continue;

        if (page_info->state == WX_STATE_STEPPING &&
            page_info->stepping_task == current) {
            page_addr = page_info->page_addr;
            pfn_shadow = page_info->pfn_shadow;
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
        pr_info("wxshadow: step handler: VMA gone for addr=%lx, auto cleanup\n", page_addr);
        wxshadow_auto_cleanup_page(page_info, "VMA Gone during step");
        kfunc_mmput(mm);
        kfunc_user_disable_single_step(current);
        return DBG_HOOK_HANDLED;
    }

    if (!wxshadow_validate_page_mapping(mm, vma, page_info, page_addr)) {
        pr_info("wxshadow: step handler: mapping changed for addr=%lx, auto cleanup\n", page_addr);
        wxshadow_auto_cleanup_page(page_info, "Mapping changed during step");
        kfunc_mmput(mm);
        kfunc_user_disable_single_step(current);
        return DBG_HOOK_HANDLED;
    }

    prot = 0;

    wxshadow_switch_mapping(vma, page_addr, pfn_shadow, prot);

    wxshadow_flush_icache_page(page_addr);

    pr_info("wxshadow: step done at pc=%llx, switched back to shadow\n",
            regs->pc);

    spin_lock(&global_lock);
    if (page_info && page_info->state == WX_STATE_STEPPING &&
        page_info->stepping_task == current) {
        page_info->state = WX_STATE_SHADOW_X;
        page_info->stepping_task = NULL;
        pr_info("wxshadow: step: state updated to SHADOW_X\n");
    } else {
        pr_err("wxshadow: step: state update SKIPPED! page_info=%px state=%d task=%px current=%px\n",
               page_info, page_info ? page_info->state : -1,
               page_info ? page_info->stepping_task : NULL, current);
    }
    spin_unlock(&global_lock);

    kfunc_mmput(mm);

    kfunc_user_disable_single_step(current);

    return DBG_HOOK_HANDLED;
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
