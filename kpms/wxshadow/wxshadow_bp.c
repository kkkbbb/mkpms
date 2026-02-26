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
    page_info = wxshadow_find_page(mm, page_addr);  /* caller ref if non-NULL */
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
        wxshadow_flush_kern_dcache_area(shadow_vaddr + (offset & ~63UL), 64);
        wxshadow_flush_icache_page(addr);
        pr_info("wxshadow: bp at %lx (existing page)\n", addr);
        wxshadow_page_put(page_info);  /* release caller ref */
        return 0;
    }

    /* Page found but shadow_page is NULL (race with concurrent set_bp):
     * release the spurious ref and fall through to create a new page. */
    if (page_info) {
        wxshadow_page_put(page_info);
        page_info = NULL;
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

    /* Validate orig_kaddr is a valid kernel address */
    if (!is_kva((unsigned long)orig_kaddr)) {
        pr_err("wxshadow: [set_bp] invalid orig_kaddr %px for pfn %lx\n",
               orig_kaddr, orig_pfn);
        wxshadow_free_page(page_info);
        return -14;
    }

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

    /* Allocate backup copy of original page */
    {
        unsigned long backup_vaddr = kfunc___get_free_pages(0xcc0, 0);
        if (!backup_vaddr) {
            pr_err("wxshadow: [set_bp] failed to allocate orig_backup page\n");
            kfunc_free_pages(shadow_vaddr, 0);
            page_info->shadow_page = NULL;
            page_info->pfn_shadow = 0;
            wxshadow_free_page(page_info);
            return -12;
        }
        memcpy((void *)backup_vaddr, orig_kaddr, PAGE_SIZE);
        page_info->orig_backup = (void *)backup_vaddr;
        page_info->pfn_orig_backup = kaddr_to_pfn(backup_vaddr);
    }

    /* Copy original to shadow and write BRK */
    memcpy((void *)shadow_vaddr, orig_kaddr, PAGE_SIZE);
    *(u32 *)(shadow_vaddr + offset) = WXSHADOW_BRK_INSN;

    page_info->state = WX_STATE_SHADOW_X;
    page_info->nr_bps = 1;
    memset(&page_info->bps[0], 0, sizeof(page_info->bps[0]));
    page_info->bps[0].addr = addr;
    page_info->bps[0].active = true;

    /* Clean dcache at kernel VA so BRK is visible at PoU */
    wxshadow_flush_kern_dcache_area(shadow_vaddr, PAGE_SIZE);

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
        if (page_info->orig_backup) {
            kfunc_free_pages((unsigned long)page_info->orig_backup, 0);
            page_info->orig_backup = NULL;
            page_info->pfn_orig_backup = 0;
        }
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

    page_info = wxshadow_find_page(mm, addr);  /* caller ref */
    if (!page_info)
        return -2;  /* ENOENT */

    bp = wxshadow_find_bp(page_info, addr);
    if (!bp) {
        wxshadow_page_put(page_info);
        return -2;
    }

    /* Find existing or add new reg mod */
    for (i = 0; i < bp->nr_reg_mods; i++) {
        if (bp->reg_mods[i].reg_idx == reg_idx) {
            bp->reg_mods[i].value = value;
            bp->reg_mods[i].enabled = true;
            pr_info("wxshadow: updated reg mod at %lx: x%d=%lx\n",
                    addr, reg_idx, value);
            wxshadow_page_put(page_info);
            return 0;
        }
    }

    if (bp->nr_reg_mods >= WXSHADOW_MAX_REG_MODS) {
        wxshadow_page_put(page_info);
        return -28;  /* ENOSPC */
    }

    i = bp->nr_reg_mods++;
    bp->reg_mods[i].reg_idx = reg_idx;
    bp->reg_mods[i].value = value;
    bp->reg_mods[i].enabled = true;

    pr_info("wxshadow: added reg mod at %lx: x%d=%lx\n", addr, reg_idx, value);
    wxshadow_page_put(page_info);
    return 0;
}

/* ========== Patch: Write data to shadow page via kernel VA ========== */

int wxshadow_do_patch(void *mm, unsigned long addr, void __user *buf, unsigned long len)
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
    void *tmpbuf;

    pr_info("wxshadow: [patch] addr=%lx len=%lu\n", addr, len);

    /* Validate parameters */
    if (len == 0 || offset + len > PAGE_SIZE) {
        pr_err("wxshadow: [patch] invalid len=%lu offset=%lu (must not cross page)\n",
               len, offset);
        return -22;  /* EINVAL */
    }

    /* Check TLB flush capability */
    if (check_tlb_flush_capability() < 0) {
        pr_err("wxshadow: [patch] no TLB flush method available!\n");
        return -38;  /* ENOSYS */
    }

    /*
     * Read user buffer via page table walk + kernel linear map.
     * _copy_from_user is unreliable on some kernels (only copies 4 bytes),
     * so we bypass it entirely by walking the user page tables to find the
     * physical page backing the user buffer, then memcpy from kernel VA.
     */
    {
        void *caller_mm = kfunc_get_task_mm(current);
        unsigned long ubuf = (unsigned long)buf;
        unsigned long buf_page = ubuf & PAGE_MASK;
        unsigned long buf_off = ubuf & ~PAGE_MASK;
        u64 *buf_pte;
        unsigned long buf_pfn;
        void *buf_kaddr;

        if (!caller_mm) {
            pr_err("wxshadow: [patch] cannot get caller mm\n");
            return -3;
        }

        /* Validate buffer doesn't cross page boundary */
        if (buf_off + len > PAGE_SIZE) {
            pr_err("wxshadow: [patch] user buffer crosses page boundary\n");
            kfunc_mmput(caller_mm);
            return -14;
        }

        buf_pte = get_user_pte(caller_mm, buf_page, NULL);
        if (!buf_pte || !(*buf_pte & PTE_VALID)) {
            pr_err("wxshadow: [patch] cannot find PTE for user buffer %lx\n", ubuf);
            kfunc_mmput(caller_mm);
            return -14;
        }

        buf_pfn = (*buf_pte >> PAGE_SHIFT) & 0xFFFFFFFFFUL;
        buf_kaddr = pfn_to_kaddr(buf_pfn);

        if (!is_kva((unsigned long)buf_kaddr)) {
            pr_err("wxshadow: [patch] invalid kaddr for user buffer pfn %lx\n", buf_pfn);
            kfunc_mmput(caller_mm);
            return -14;
        }

        tmpbuf = kfunc_kzalloc ? kfunc_kzalloc(len, 0xcc0) : NULL;
        if (!tmpbuf) {
            pr_err("wxshadow: [patch] failed to alloc temp buffer\n");
            kfunc_mmput(caller_mm);
            return -12;
        }

        memcpy(tmpbuf, (char *)buf_kaddr + buf_off, len);
        kfunc_mmput(caller_mm);

        pr_info("wxshadow: [patch] read %lu bytes from user buf via PTE walk (pfn=%lx)\n",
                len, buf_pfn);
    }

    /* Find VMA first (lockless) */
    vma = kfunc_find_vma(mm, addr);
    if (!vma || vma_start(vma) > addr) {
        pr_err("wxshadow: [patch] no vma for %lx\n", addr);
        kfunc_kfree(tmpbuf);
        return -1;
    }

    /* Check if page already has shadow */
    page_info = wxshadow_find_page(mm, page_addr);  /* caller ref if non-NULL */
    if (page_info && page_info->shadow_page) {
        /* Shadow already exists, write patch data directly via memcpy */
        shadow_vaddr = (unsigned long)page_info->shadow_page;
        memcpy((void *)(shadow_vaddr + offset), tmpbuf, len);

        /* Clean dcache at kernel VA so data is visible at PoU */
        wxshadow_flush_kern_dcache_area(shadow_vaddr, PAGE_SIZE);

        /* If not already in SHADOW_X state, switch PTE */
        if (page_info->state != WX_STATE_SHADOW_X) {
            prot = 0;  /* --x */
            ret = wxshadow_switch_mapping(vma, page_addr, page_info->pfn_shadow, prot);
            if (ret == 0)
                page_info->state = WX_STATE_SHADOW_X;
        }

        wxshadow_flush_icache_page(page_addr);
        pr_info("wxshadow: [patch] patched existing shadow at %lx+%lx (%lu bytes)\n",
                page_addr, offset, len);
        kfunc_kfree(tmpbuf);
        wxshadow_page_put(page_info);  /* release caller ref */
        return ret;
    }

    /* Page found but shadow_page is NULL: release spurious ref and fall through. */
    if (page_info) {
        wxshadow_page_put(page_info);
        page_info = NULL;
    }

    /* No shadow yet - create one */
    page_info = wxshadow_create_page(mm, page_addr);
    if (!page_info) {
        pr_err("wxshadow: [patch] failed to create page structure\n");
        kfunc_kfree(tmpbuf);
        return -12;  /* ENOMEM */
    }

    /* Get original page PFN from PTE (lockless) */
    pte = get_user_pte(mm, page_addr, NULL);
    if (!pte || !(*pte & PTE_VALID)) {
        pr_err("wxshadow: [patch] no pte for %lx\n", page_addr);
        kfunc_kfree(tmpbuf);
        wxshadow_free_page(page_info);
        return -14;
    }
    orig_pfn = (*pte >> PAGE_SHIFT) & 0xFFFFFFFFFUL;

    page_info->pfn_original = orig_pfn;
    orig_kaddr = pfn_to_kaddr(orig_pfn);

    /* Validate orig_kaddr is a valid kernel address */
    if (!is_kva((unsigned long)orig_kaddr)) {
        pr_err("wxshadow: [patch] invalid orig_kaddr %px for pfn %lx\n",
               orig_kaddr, orig_pfn);
        kfunc_kfree(tmpbuf);
        wxshadow_free_page(page_info);
        return -14;
    }

    /* Allocate shadow page (single page, order=0) */
    shadow_vaddr = kfunc___get_free_pages(0xcc0, 0);
    if (!shadow_vaddr) {
        pr_err("wxshadow: [patch] failed to allocate shadow page\n");
        kfunc_kfree(tmpbuf);
        wxshadow_free_page(page_info);
        return -12;
    }

    shadow_pfn = kaddr_to_pfn(shadow_vaddr);
    page_info->pfn_shadow = shadow_pfn;
    page_info->shadow_page = (void *)shadow_vaddr;

    /* Allocate backup copy of original page */
    {
        unsigned long backup_vaddr = kfunc___get_free_pages(0xcc0, 0);
        if (!backup_vaddr) {
            pr_err("wxshadow: [patch] failed to allocate orig_backup page\n");
            kfunc_kfree(tmpbuf);
            kfunc_free_pages(shadow_vaddr, 0);
            page_info->shadow_page = NULL;
            page_info->pfn_shadow = 0;
            wxshadow_free_page(page_info);
            return -12;
        }
        memcpy((void *)backup_vaddr, orig_kaddr, PAGE_SIZE);
        page_info->orig_backup = (void *)backup_vaddr;
        page_info->pfn_orig_backup = kaddr_to_pfn(backup_vaddr);
    }

    /* Copy original to shadow */
    memcpy((void *)shadow_vaddr, orig_kaddr, PAGE_SIZE);

    /* Write patch data from temp buffer to shadow via memcpy */
    memcpy((void *)(shadow_vaddr + offset), tmpbuf, len);
    kfunc_kfree(tmpbuf);
    tmpbuf = NULL;

    page_info->state = WX_STATE_SHADOW_X;
    page_info->nr_bps = 0;  /* No breakpoints */

    /* Clean dcache at kernel VA so data is visible at PoU for instruction fetch */
    wxshadow_flush_kern_dcache_area(shadow_vaddr, PAGE_SIZE);

    /* Switch PTE to shadow page with --x permission */
    prot = 0;  /* --x */
    ret = wxshadow_switch_mapping(vma, page_addr, shadow_pfn, prot);

    if (ret == 0) {
        wxshadow_flush_icache_page(page_addr);
        pr_info("wxshadow: [patch] created shadow at %lx+%lx (%lu bytes) orig_pfn=%lx shadow_pfn=%lx\n",
                page_addr, offset, len, page_info->pfn_original, page_info->pfn_shadow);
    } else {
        pr_err("wxshadow: [patch] switch failed\n");
        kfunc_free_pages(shadow_vaddr, 0);
        page_info->shadow_page = NULL;
        page_info->pfn_shadow = 0;
        if (page_info->orig_backup) {
            kfunc_free_pages((unsigned long)page_info->orig_backup, 0);
            page_info->orig_backup = NULL;
            page_info->pfn_orig_backup = 0;
        }
        wxshadow_free_page(page_info);
    }

    return ret;
}

/* ========== Release: Release shadow page ========== */

int wxshadow_do_release(void *mm, unsigned long addr)
{
    struct wxshadow_page *page_info;
    void *vma;
    unsigned long page_addr = addr & PAGE_MASK;
    u64 prot;

    pr_info("wxshadow: [release] addr=%lx\n", addr);

    /* Find page */
    page_info = wxshadow_find_page(mm, page_addr);
    if (!page_info) {
        pr_err("wxshadow: [release] page not found for %lx\n", addr);
        return -2;  /* ENOENT */
    }

    /* Find VMA */
    vma = kfunc_find_vma(mm, addr);
    if (vma && vma_start(vma) <= addr) {
        /* Switch back to original page with r-x permission */
        if (page_info->pfn_original) {
            prot = PTE_USER | PTE_RDONLY;  /* r-x */
            wxshadow_switch_mapping(vma, page_addr, page_info->pfn_original, prot);
            pr_info("wxshadow: [release] restored original mapping for %lx\n", page_addr);
        }
    }

    /* auto_cleanup: marks dead, captures shadow, removes from list, puts list ref. */
    wxshadow_auto_cleanup_page(page_info, "user release");
    wxshadow_page_put(page_info);  /* release caller ref → kfree */
    pr_info("wxshadow: [release] cleaned up page structure for %lx\n", page_addr);

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

    page_info = wxshadow_find_page(mm, addr);  /* caller ref */
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

    if (bp_idx < 0) {
        wxshadow_page_put(page_info);
        return -2;
    }

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
            if (!is_kva((unsigned long)orig_kaddr)) {
                pr_err("wxshadow: [del_bp] invalid orig_kaddr %px\n", orig_kaddr);
                wxshadow_page_put(page_info);
                return -14;
            }
            orig_insn = *(u32 *)((char *)orig_kaddr + offset);

            shadow_kaddr = page_info->shadow_page;
            *(u32 *)((char *)shadow_kaddr + offset) = orig_insn;

            wxshadow_flush_icache_page(addr);
        }
        wxshadow_page_put(page_info);  /* release caller ref; page stays in list */
        return 0;
    }

    /* Last BP - restore PTE then remove page from list and free. */
    vma = kfunc_find_vma(mm, addr);
    if (vma && vma_start(vma) <= addr) {
        if (page_info->state != WX_STATE_NONE && page_info->shadow_page) {
            /* Switch back to original */
            prot = PTE_USER | PTE_RDONLY;
            wxshadow_switch_mapping(vma, page_addr, page_info->pfn_original, prot);
            pr_info("wxshadow: restored original mapping for %lx\n", page_addr);
        }
    }

    /* auto_cleanup: marks dead, captures shadow, removes from list, puts list ref. */
    wxshadow_auto_cleanup_page(page_info, "last bp removed");
    wxshadow_page_put(page_info);  /* release caller ref → kfree */
    pr_info("wxshadow: cleaned up page structure for %lx\n", page_addr);

    return 0;
}

/* ========== Delete all breakpoints for mm ========== */

/*
 * Helper: restore and free a single page (must be called WITHOUT global_lock)
 */
static void release_one_page(void *mm, struct wxshadow_page *page)
{
    void *vma;
    u64 prot;

    /* Disable single step if task is stepping */
    if (page->stepping_task && kfunc_user_disable_single_step) {
        kfunc_user_disable_single_step(page->stepping_task);
        page->stepping_task = NULL;
    }

    /* Restore original page mapping */
    if (page->pfn_original && page->state != WX_STATE_NONE) {
        vma = kfunc_find_vma(mm, page->page_addr);
        if (vma && vma_start(vma) <= page->page_addr) {
            prot = PTE_USER | PTE_RDONLY;  /* r-x */
            wxshadow_switch_mapping(vma, page->page_addr,
                                    page->pfn_original, prot);
            wxshadow_flush_icache_page(page->page_addr);
        }
    }

    /* Shadow page memory and page struct freed by caller (collect_and_release_pages). */
}

/*
 * collect_and_release_pages - iteratively pop and release all pages for mm.
 *
 * Uses a simple "find first match, pop under lock, release outside lock" loop.
 * No intermediate allocation needed; eliminates TOCTOU races.
 */
static int collect_and_release_pages(void *mm)
{
    struct list_head *pos, *n;
    struct wxshadow_page *page;
    unsigned long shadow_vaddr;
    unsigned long backup_vaddr;
    int count = 0;

    while (1) {
        /* Pop the first page belonging to mm under the lock.
         * Capture shadow_vaddr/backup_vaddr and clear pointers under the lock so
         * concurrent handlers cannot double-free them. */
        page = NULL;
        shadow_vaddr = 0;
        backup_vaddr = 0;
        spin_lock(&global_lock);
        list_for_each_safe(pos, n, &page_list) {
            struct wxshadow_page *p =
                container_of(pos, struct wxshadow_page, list);
            if (p->mm == mm) {
                shadow_vaddr = (unsigned long)p->shadow_page;
                p->shadow_page = NULL;
                backup_vaddr = (unsigned long)p->orig_backup;
                p->orig_backup = NULL;
                p->dead = true;
                list_del_init(&p->list);
                page = p;
                break;
            }
        }
        spin_unlock(&global_lock);

        if (!page)
            break;

        /* Free shadow page and orig_backup outside the lock (may sleep/schedule). */
        if (shadow_vaddr)
            kfunc_free_pages(shadow_vaddr, 0);
        if (backup_vaddr)
            kfunc_free_pages(backup_vaddr, 0);

        pr_info("wxshadow: [release_all] releasing page addr=%lx state=%d\n",
                page->page_addr, page->state);
        release_one_page(mm, page);
        wxshadow_page_put(page);  /* release list ref → kfree when refcount hits 0 */
        count++;
    }

    if (count > 0)
        pr_info("wxshadow: [release_all] cleaned up %d pages\n", count);
    return 0;
}

int wxshadow_do_del_all_bp(void *mm)
{
    pr_info("wxshadow: [del_all_bp] mm=%px\n", mm);
    return collect_and_release_pages(mm);
}

/* ========== Release all shadow pages for mm ========== */

int wxshadow_do_release_all(void *mm)
{
    pr_info("wxshadow: [release_all] mm=%px\n", mm);
    return collect_and_release_pages(mm);
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
        option == PR_WXSHADOW_DEL_BP || option == PR_WXSHADOW_PATCH ||
        option == PR_WXSHADOW_RELEASE) {
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
        if (arg3 == 0)
            ret = wxshadow_do_del_all_bp(mm);
        else
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

    case PR_WXSHADOW_PATCH:
        pid = (pid_t)arg2;
        pr_info("wxshadow: [prctl] PATCH pid=%d addr=%lx buf=%lx len=%lu\n",
                pid, arg3, arg4, arg5);
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
        ret = wxshadow_do_patch(mm, arg3, (void __user *)arg4, arg5);
        kfunc_mmput(mm);
        args->ret = ret;
        args->skip_origin = 1;
        break;

    case PR_WXSHADOW_RELEASE:
        pid = (pid_t)arg2;
        pr_info("wxshadow: [prctl] RELEASE pid=%d addr=%lx\n", pid, arg3);
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
        if (arg3 == 0)
            ret = wxshadow_do_release_all(mm);
        else
            ret = wxshadow_do_release(mm, arg3);
        kfunc_mmput(mm);
        args->ret = ret;
        args->skip_origin = 1;
        break;

    default:
        /* Not our prctl, let it pass through */
        break;
    }
}
