/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * W^X Shadow Memory KPM Module - Breakpoint Operations
 *
 * Set/delete breakpoints, set register modifications, prctl hook.
 *
 * Copyright (C) 2024
 */

#include "wxshadow_internal.h"

/* ========== TLB flush capability check ========== */

/*
 * Check if we have a working TLB flush method.
 * Returns 0 if OK, -1 if no TLB flush capability.
 */
static int check_tlb_flush_capability(void)
{
    /* Method 1: kernel flush_tlb_page */
    if (kfunc_flush_tlb_page)
        return 0;

    /* Method 2: kernel __flush_tlb_range */
    if (kfunc___flush_tlb_range)
        return 0;

    /* Method 3: TLBI fallback - requires mm_context_id_offset */
    if (mm_context_id_offset >= 0)
        return 0;

    /* No TLB flush method available */
    return -1;
}

/* ========== Set breakpoint ========== */

int wxshadow_do_set_bp(void *mm, unsigned long addr)
{
    void *vma;
    struct wxshadow_page *page_info;
    unsigned long shadow_vaddr;
    void *orig_kaddr;
    unsigned long page_addr = addr & PAGE_MASK;
    unsigned long offset = addr & ~PAGE_MASK;
    int ret = 0;
    u64 *pte;
    unsigned long orig_pfn, shadow_pfn;
    u64 prot;

    pr_info("wxshadow: [set_bp] addr=%lx\n", addr);

    /* Check TLB flush capability */
    if (check_tlb_flush_capability() < 0) {
        pr_err("wxshadow: [set_bp] no TLB flush method available!\n");
        pr_err("wxshadow: [set_bp] need flush_tlb_page, __flush_tlb_range, or mm_context_id_offset\n");
        return -38;  /* ENOSYS */
    }

    /* Log which TLB flush method is being used */
    if (!kfunc_flush_tlb_page && !kfunc___flush_tlb_range) {
        pr_info("wxshadow: [set_bp] using TLBI instruction with ASID (context_id_offset=0x%x)\n",
                mm_context_id_offset);
    }

    /* Find VMA first (lockless) */
    vma = kfunc_find_vma(mm, addr);
    if (!vma || vma_start(vma) > addr) {
        pr_err("wxshadow: [set_bp] no vma for %lx\n", addr);
        return -1;
    }

    /* Check if page already has shadow */
    page_info = wxshadow_find_page(mm, page_addr);
    if (page_info && page_info->shadow_page) {
        int bp_idx = -1;
        int i;

        /* Find or create bp entry */
        for (i = 0; i < page_info->nr_bps; i++) {
            if (page_info->bps[i].addr == addr) {
                bp_idx = i;
                break;
            }
        }
        if (bp_idx < 0 && page_info->nr_bps < WXSHADOW_MAX_BPS_PER_PAGE) {
            bp_idx = page_info->nr_bps++;
            memset(&page_info->bps[bp_idx], 0, sizeof(page_info->bps[bp_idx]));
            page_info->bps[bp_idx].addr = addr;
            page_info->bps[bp_idx].active = true;
        }

        /* Write BRK to existing shadow */
        shadow_vaddr = (unsigned long)page_info->shadow_page;
        *(u32 *)(shadow_vaddr + offset) = WXSHADOW_BRK_INSN;
        wxshadow_flush_icache_page(addr);
        pr_info("wxshadow: bp at %lx (existing page)\n", addr);
        return 0;
    }

    /* Create new page structure */
    page_info = wxshadow_create_page(mm, page_addr);
    if (!page_info) {
        pr_err("wxshadow: [set_bp] failed to create page structure\n");
        return -12;
    }

    /* Get original page PFN from PTE (lockless) */
    pte = get_user_pte(mm, page_addr, NULL);
    if (!pte || !(*pte & PTE_VALID)) {
        pr_err("wxshadow: [set_bp] no pte for %lx\n", page_addr);
        wxshadow_free_page(page_info);
        return -14;
    }
    orig_pfn = (*pte >> PAGE_SHIFT) & 0xFFFFFFFFFUL;

    page_info->pfn_original = orig_pfn;
    orig_kaddr = pfn_to_kaddr(orig_pfn);

    /* Allocate shadow page (single page, order=0) */
    shadow_vaddr = kfunc___get_free_pages(0xcc0, 0);
    if (!shadow_vaddr) {
        pr_err("wxshadow: [set_bp] failed to allocate shadow page\n");
        wxshadow_free_page(page_info);
        return -12;
    }

    shadow_pfn = kaddr_to_pfn(shadow_vaddr);
    page_info->pfn_shadow = shadow_pfn;
    page_info->shadow_page = (void *)shadow_vaddr;

    /* Copy original to shadow and write BRK */
    memcpy((void *)shadow_vaddr, orig_kaddr, PAGE_SIZE);
    *(u32 *)(shadow_vaddr + offset) = WXSHADOW_BRK_INSN;

    page_info->state = WX_STATE_SHADOW_X;
    page_info->nr_bps = 1;
    memset(&page_info->bps[0], 0, sizeof(page_info->bps[0]));
    page_info->bps[0].addr = addr;
    page_info->bps[0].active = true;

    /* Switch PTE to shadow page */
    prot = 0;
    ret = wxshadow_switch_mapping(vma, page_addr, shadow_pfn, prot);

    if (ret == 0) {
        wxshadow_flush_icache_page(page_addr);
        pr_info("wxshadow: bp at %lx orig_pfn=%lx shadow_pfn=%lx\n",
                addr, page_info->pfn_original, page_info->pfn_shadow);
    } else {
        pr_err("wxshadow: [set_bp] switch failed\n");
        kfunc_free_pages(shadow_vaddr, 0);
        page_info->shadow_page = NULL;
        page_info->pfn_shadow = 0;
        wxshadow_free_page(page_info);
    }

    return ret;
}

/* ========== Set register modification ========== */

int wxshadow_do_set_reg(void *mm, unsigned long addr,
                        unsigned int reg_idx, unsigned long value)
{
    struct wxshadow_page *page_info;
    struct wxshadow_bp *bp;
    int i;

    if (reg_idx > 31)
        return -22;  /* EINVAL */

    page_info = wxshadow_find_page(mm, addr);
    if (!page_info)
        return -2;  /* ENOENT */

    bp = wxshadow_find_bp(page_info, addr);
    if (!bp)
        return -2;

    /* Find existing or add new reg mod */
    for (i = 0; i < bp->nr_reg_mods; i++) {
        if (bp->reg_mods[i].reg_idx == reg_idx) {
            bp->reg_mods[i].value = value;
            bp->reg_mods[i].enabled = true;
            pr_info("wxshadow: updated reg mod at %lx: x%d=%lx\n",
                    addr, reg_idx, value);
            return 0;
        }
    }

    if (bp->nr_reg_mods >= WXSHADOW_MAX_REG_MODS)
        return -28;  /* ENOSPC */

    i = bp->nr_reg_mods++;
    bp->reg_mods[i].reg_idx = reg_idx;
    bp->reg_mods[i].value = value;
    bp->reg_mods[i].enabled = true;

    pr_info("wxshadow: added reg mod at %lx: x%d=%lx\n", addr, reg_idx, value);
    return 0;
}

/* ========== Delete breakpoint ========== */

int wxshadow_do_del_bp(void *mm, unsigned long addr)
{
    struct wxshadow_page *page_info;
    void *vma;
    unsigned long page_addr = addr & PAGE_MASK;
    unsigned long offset = addr & ~PAGE_MASK;
    int i, bp_idx = -1;
    int remaining_bps = 0;
    void *shadow_kaddr, *orig_kaddr;
    u32 orig_insn;
    u64 prot;

    page_info = wxshadow_find_page(mm, addr);
    if (!page_info)
        return -2;

    /* Find the breakpoint */
    for (i = 0; i < page_info->nr_bps; i++) {
        if (page_info->bps[i].active && page_info->bps[i].addr == addr) {
            bp_idx = i;
        } else if (page_info->bps[i].active) {
            remaining_bps++;
        }
    }

    if (bp_idx < 0)
        return -2;

    /* Deactivate breakpoint */
    page_info->bps[bp_idx].active = false;
    memset(&page_info->bps[bp_idx].reg_mods, 0,
           sizeof(page_info->bps[bp_idx].reg_mods));
    page_info->bps[bp_idx].nr_reg_mods = 0;

    pr_info("wxshadow: del bp at %lx\n", addr);

    if (remaining_bps > 0) {
        /* Restore original instruction in shadow */
        if (page_info->shadow_page && page_info->pfn_original) {
            orig_kaddr = pfn_to_kaddr(page_info->pfn_original);
            orig_insn = *(u32 *)((char *)orig_kaddr + offset);

            shadow_kaddr = page_info->shadow_page;
            *(u32 *)((char *)shadow_kaddr + offset) = orig_insn;

            wxshadow_flush_icache_page(addr);
        }
        return 0;
    }

    /* Last BP - cleanup shadow page and free page structure */
    vma = kfunc_find_vma(mm, addr);
    if (vma && vma_start(vma) <= addr) {
        if (page_info->state != WX_STATE_NONE && page_info->shadow_page) {
            /* Switch back to original */
            prot = PTE_USER | PTE_RDONLY;
            wxshadow_switch_mapping(vma, page_addr, page_info->pfn_original, prot);
            pr_info("wxshadow: restored original mapping for %lx\n", page_addr);
        }
    }

    /* Free the page structure (also frees shadow page) */
    wxshadow_free_page(page_info);
    pr_info("wxshadow: cleaned up page structure for %lx\n", page_addr);

    return 0;
}

/* ========== prctl hook ========== */

void prctl_before(hook_fargs4_t *args, void *udata)
{
    int option = (int)syscall_argn(args, 0);
    unsigned long arg2 = syscall_argn(args, 1);
    unsigned long arg3 = syscall_argn(args, 2);
    unsigned long arg4 = syscall_argn(args, 3);
    unsigned long arg5 = syscall_argn(args, 4);
    void *mm;
    void *task;
    int ret = -22;  /* EINVAL */
    pid_t pid;

    /* Lazy scan mm->context.id offset on first wxshadow prctl call */
    if (option == PR_WXSHADOW_SET_BP || option == PR_WXSHADOW_SET_REG ||
        option == PR_WXSHADOW_DEL_BP) {
        if (mm_context_id_offset < 0) {
            /* Now in user process context, TTBR0 should have valid ASID */
            try_scan_mm_context_id_offset();
        }
    }

    switch (option) {
    case PR_WXSHADOW_SET_BP:
        pid = (pid_t)arg2;
        pr_info("wxshadow: [prctl] SET_BP pid=%d addr=%lx\n", pid, arg3);
        if (pid == 0) {
            pr_info("wxshadow: [prctl] SET_BP using current task\n");
            mm = kfunc_get_task_mm(current);
            if (!mm) {
                pr_err("wxshadow: [prctl] SET_BP get_task_mm(current) failed\n");
                args->ret = -3;
                args->skip_origin = 1;
                return;
            }
        } else {
            pr_info("wxshadow: [prctl] SET_BP looking up pid=%d\n", pid);
            kfunc_rcu_read_lock();
            task = wxfunc(find_task_by_vpid)(pid);
            if (!task) {
                pr_err("wxshadow: [prctl] SET_BP find_task_by_vpid failed\n");
                kfunc_rcu_read_unlock();
                args->ret = -3;
                args->skip_origin = 1;
                return;
            }
            pr_info("wxshadow: [prctl] SET_BP found task=%px\n", task);
            mm = kfunc_get_task_mm(task);
            kfunc_rcu_read_unlock();
            if (!mm) {
                pr_err("wxshadow: [prctl] SET_BP get_task_mm failed\n");
                args->ret = -3;
                args->skip_origin = 1;
                return;
            }
        }
        pr_info("wxshadow: [prctl] SET_BP mm=%px, calling do_set_bp\n", mm);
        ret = wxshadow_do_set_bp(mm, arg3);
        pr_info("wxshadow: [prctl] SET_BP do_set_bp returned %d\n", ret);
        kfunc_mmput(mm);
        args->ret = ret;
        args->skip_origin = 1;
        break;

    case PR_WXSHADOW_SET_REG:
        pid = (pid_t)arg2;
        if (pid == 0) {
            mm = kfunc_get_task_mm(current);
            if (!mm) {
                args->ret = -3;
                args->skip_origin = 1;
                return;
            }
        } else {
            kfunc_rcu_read_lock();
            task = wxfunc(find_task_by_vpid)(pid);
            if (!task) {
                kfunc_rcu_read_unlock();
                args->ret = -3;
                args->skip_origin = 1;
                return;
            }
            mm = kfunc_get_task_mm(task);
            kfunc_rcu_read_unlock();
            if (!mm) {
                args->ret = -3;
                args->skip_origin = 1;
                return;
            }
        }
        ret = wxshadow_do_set_reg(mm, arg3, (unsigned int)arg4, arg5);
        kfunc_mmput(mm);
        args->ret = ret;
        args->skip_origin = 1;
        break;

    case PR_WXSHADOW_DEL_BP:
        pid = (pid_t)arg2;
        if (pid == 0) {
            mm = kfunc_get_task_mm(current);
            if (!mm) {
                args->ret = -3;
                args->skip_origin = 1;
                return;
            }
        } else {
            kfunc_rcu_read_lock();
            task = wxfunc(find_task_by_vpid)(pid);
            if (!task) {
                kfunc_rcu_read_unlock();
                args->ret = -3;
                args->skip_origin = 1;
                return;
            }
            mm = kfunc_get_task_mm(task);
            kfunc_rcu_read_unlock();
            if (!mm) {
                args->ret = -3;
                args->skip_origin = 1;
                return;
            }
        }
        ret = wxshadow_do_del_bp(mm, arg3);
        kfunc_mmput(mm);
        args->ret = ret;
        args->skip_origin = 1;
        break;

    case PR_WXSHADOW_SET_TLB_MODE:
        /* arg2 = mode (0=auto, 1=precise, 2=broadcast, 3=full) */
        if (arg2 > WX_TLB_MODE_FULL) {
            pr_err("wxshadow: [prctl] invalid TLB mode: %lu\n", arg2);
            args->ret = -22;  /* EINVAL */
        } else {
            int old_mode = tlb_flush_mode;
            tlb_flush_mode = (int)arg2;
            pr_info("wxshadow: [prctl] TLB mode changed: %d -> %d\n",
                    old_mode, tlb_flush_mode);
            args->ret = 0;
        }
        args->skip_origin = 1;
        break;

    case PR_WXSHADOW_GET_TLB_MODE:
        /* Return current TLB flush mode */
        args->ret = tlb_flush_mode;
        args->skip_origin = 1;
        pr_info("wxshadow: [prctl] GET_TLB_MODE = %d\n", tlb_flush_mode);
        break;

    default:
        /* Not our prctl, let it pass through */
        break;
    }
}
