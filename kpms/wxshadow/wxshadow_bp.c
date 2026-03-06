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

    /* Split PMD block if needed (THP) */
    ret = wxshadow_try_split_pmd(mm, vma, page_addr);
    if (ret < 0) {
        pr_err("wxshadow: [set_bp] PMD split failed for %lx: %d\n", page_addr, ret);
        return ret;
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

/* ========== User buffer read via PTE walk ========== */

/*
 * Read data from a user-space buffer by walking the caller's page tables.
 *
 * _copy_from_user is unreliable on some kernels (only copies first 4 bytes),
 * so we bypass it: walk user page tables → find physical page → memcpy from
 * kernel linear map.  Returns a kmalloc'd buffer on success, NULL on failure.
 * Caller must kfunc_kfree() the returned buffer.
 */
static void *copy_from_user_via_pte(void __user *ubuf, unsigned long len)
{
    void *caller_mm;
    unsigned long uaddr = (unsigned long)ubuf;
    unsigned long buf_page = uaddr & PAGE_MASK;
    unsigned long buf_off = uaddr & ~PAGE_MASK;
    u64 *buf_pte;
    unsigned long buf_pfn;
    void *buf_kaddr, *kbuf;

    if (buf_off + len > PAGE_SIZE) {
        pr_err("wxshadow: user buffer %lx+%lu crosses page boundary\n", uaddr, len);
        return NULL;
    }

    caller_mm = kfunc_get_task_mm(current);
    if (!caller_mm)
        return NULL;

    /* Split PMD block if user buffer is in THP */
    {
        void *buf_vma = kfunc_find_vma(caller_mm, uaddr);
        if (buf_vma && vma_start(buf_vma) <= uaddr)
            wxshadow_try_split_pmd(caller_mm, buf_vma, buf_page);
    }

    buf_pte = get_user_pte(caller_mm, buf_page, NULL);
    if (!buf_pte || !(*buf_pte & PTE_VALID)) {
        pr_err("wxshadow: no PTE for user buffer %lx\n", uaddr);
        kfunc_mmput(caller_mm);
        return NULL;
    }

    buf_pfn = (*buf_pte >> PAGE_SHIFT) & 0xFFFFFFFFFUL;
    buf_kaddr = pfn_to_kaddr(buf_pfn);
    if (!is_kva((unsigned long)buf_kaddr)) {
        kfunc_mmput(caller_mm);
        return NULL;
    }

    kbuf = kfunc_kzalloc(len, 0xcc0);
    if (!kbuf) {
        kfunc_mmput(caller_mm);
        return NULL;
    }

    memcpy(kbuf, (char *)buf_kaddr + buf_off, len);
    kfunc_mmput(caller_mm);
    return kbuf;
}

/* ========== Patch: Write data to shadow page via kernel VA ========== */

int wxshadow_do_patch(void *mm, unsigned long addr, void __user *buf, unsigned long len)
{
    struct wxshadow_page *page_info;
    unsigned long page_addr = addr & PAGE_MASK;
    unsigned long offset = addr & ~PAGE_MASK;
    unsigned long shadow_vaddr, orig_pfn, shadow_pfn;
    void *vma, *orig_kaddr, *patch_data;
    u64 *pte;
    int ret;

    pr_info("wxshadow: [patch] addr=%lx len=%lu\n", addr, len);

    if (len == 0 || offset + len > PAGE_SIZE) {
        pr_err("wxshadow: [patch] invalid len=%lu offset=%lu\n", len, offset);
        return -22;  /* EINVAL */
    }
    if (check_tlb_flush_capability() < 0)
        return -38;  /* ENOSYS */

    /* Read user buffer into kernel memory via PTE walk */
    patch_data = copy_from_user_via_pte(buf, len);
    if (!patch_data)
        return -14;  /* EFAULT */

    vma = kfunc_find_vma(mm, addr);
    if (!vma || vma_start(vma) > addr) {
        pr_err("wxshadow: [patch] no vma for %lx\n", addr);
        ret = -1;
        goto out_free;
    }

    /* Split PMD block if needed (THP) */
    ret = wxshadow_try_split_pmd(mm, vma, page_addr);
    if (ret < 0) {
        pr_err("wxshadow: [patch] PMD split failed for %lx: %d\n", page_addr, ret);
        goto out_free;
    }

    /* Fast path: shadow already exists */
    page_info = wxshadow_find_page(mm, page_addr);
    if (page_info && page_info->shadow_page) {
        shadow_vaddr = (unsigned long)page_info->shadow_page;
        memcpy((void *)(shadow_vaddr + offset), patch_data, len);
        wxshadow_flush_kern_dcache_area(shadow_vaddr, PAGE_SIZE);

        if (page_info->state != WX_STATE_SHADOW_X) {
            ret = wxshadow_switch_mapping(vma, page_addr, page_info->pfn_shadow, 0);
            if (ret == 0)
                page_info->state = WX_STATE_SHADOW_X;
        } else {
            ret = 0;
        }

        wxshadow_flush_icache_page(page_addr);
        pr_info("wxshadow: [patch] existing shadow %lx+%lx (%lu bytes)\n",
                page_addr, offset, len);
        wxshadow_page_put(page_info);
        goto out_free;
    }
    if (page_info) {
        wxshadow_page_put(page_info);
        page_info = NULL;
    }

    /* Slow path: create new shadow page */
    page_info = wxshadow_create_page(mm, page_addr);
    if (!page_info) { ret = -12; goto out_free; }

    pte = get_user_pte(mm, page_addr, NULL);
    if (!pte || !(*pte & PTE_VALID)) {
        ret = -14;
        goto out_free_page;
    }
    orig_pfn = (*pte >> PAGE_SHIFT) & 0xFFFFFFFFFUL;
    page_info->pfn_original = orig_pfn;
    orig_kaddr = pfn_to_kaddr(orig_pfn);
    if (!is_kva((unsigned long)orig_kaddr)) { ret = -14; goto out_free_page; }

    /* Allocate shadow + backup pages */
    shadow_vaddr = kfunc___get_free_pages(0xcc0, 0);
    if (!shadow_vaddr) { ret = -12; goto out_free_page; }
    page_info->pfn_shadow = kaddr_to_pfn(shadow_vaddr);
    page_info->shadow_page = (void *)shadow_vaddr;

    {
        unsigned long backup = kfunc___get_free_pages(0xcc0, 0);
        if (!backup) { ret = -12; goto out_free_shadow; }
        memcpy((void *)backup, orig_kaddr, PAGE_SIZE);
        page_info->orig_backup = (void *)backup;
        page_info->pfn_orig_backup = kaddr_to_pfn(backup);
    }

    /* Build shadow: original content + patch overlay */
    memcpy((void *)shadow_vaddr, orig_kaddr, PAGE_SIZE);
    memcpy((void *)(shadow_vaddr + offset), patch_data, len);

    page_info->state = WX_STATE_SHADOW_X;
    page_info->nr_bps = 0;

    wxshadow_flush_kern_dcache_area(shadow_vaddr, PAGE_SIZE);

    ret = wxshadow_switch_mapping(vma, page_addr, page_info->pfn_shadow, 0);
    if (ret == 0) {
        wxshadow_flush_icache_page(page_addr);
        pr_info("wxshadow: [patch] new shadow %lx+%lx (%lu bytes) pfn %lx->%lx\n",
                page_addr, offset, len, orig_pfn, page_info->pfn_shadow);
    } else {
        goto out_free_shadow;
    }

    kfunc_kfree(patch_data);
    return 0;

out_free_shadow:
    kfunc_free_pages(shadow_vaddr, 0);
    page_info->shadow_page = NULL;
    page_info->pfn_shadow = 0;
    if (page_info->orig_backup) {
        kfunc_free_pages((unsigned long)page_info->orig_backup, 0);
        page_info->orig_backup = NULL;
        page_info->pfn_orig_backup = 0;
    }
out_free_page:
    wxshadow_free_page(page_info);
out_free:
    kfunc_kfree(patch_data);
    return ret;
}

/* ========== Release: Release shadow page ========== */

int wxshadow_do_release(void *mm, unsigned long addr)
{
    struct wxshadow_page *page_info;
    unsigned long page_addr = addr & PAGE_MASK;

    pr_info("wxshadow: [release] addr=%lx\n", addr);

    page_info = wxshadow_find_page(mm, page_addr);
    if (!page_info) {
        pr_err("wxshadow: [release] page not found for %lx\n", addr);
        return -2;  /* ENOENT */
    }

    wxshadow_teardown_page(page_info, "user release");
    wxshadow_page_put(page_info);
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

    /* Last BP - unified teardown handles PTE restore, free, etc. */
    wxshadow_teardown_page(page_info, "last bp removed");
    wxshadow_page_put(page_info);
    return 0;
}

/* ========== prctl hook ========== */

/* Resolve pid to mm_struct. Returns mm with refcount held (caller must mmput). */
static void *resolve_pid_to_mm(pid_t pid)
{
    void *mm;

    if (pid == 0)
        return kfunc_get_task_mm(current);

    kfunc_rcu_read_lock();
    {
        void *task = wxfunc(find_task_by_vpid)(pid);
        if (!task) {
            kfunc_rcu_read_unlock();
            return NULL;
        }
        mm = kfunc_get_task_mm(task);
    }
    kfunc_rcu_read_unlock();
    return mm;
}

void prctl_before(hook_fargs4_t *args, void *udata)
{
    int option = (int)syscall_argn(args, 0);
    unsigned long arg2 = syscall_argn(args, 1);
    unsigned long arg3 = syscall_argn(args, 2);
    unsigned long arg4 = syscall_argn(args, 3);
    unsigned long arg5 = syscall_argn(args, 4);
    void *mm;
    int ret;
    pid_t pid;

    /* Lazy scan mm->context.id offset on first wxshadow prctl call */
    if (option == PR_WXSHADOW_SET_BP || option == PR_WXSHADOW_SET_REG ||
        option == PR_WXSHADOW_DEL_BP || option == PR_WXSHADOW_PATCH ||
        option == PR_WXSHADOW_RELEASE) {
        if (mm_context_id_offset < 0)
            try_scan_mm_context_id_offset();
    }

    switch (option) {
    case PR_WXSHADOW_SET_BP:
        pid = (pid_t)arg2;
        mm = resolve_pid_to_mm(pid);
        if (!mm) { args->ret = -3; args->skip_origin = 1; return; }
        ret = wxshadow_do_set_bp(mm, arg3);
        kfunc_mmput(mm);
        args->ret = ret;
        args->skip_origin = 1;
        break;

    case PR_WXSHADOW_SET_REG:
        pid = (pid_t)arg2;
        mm = resolve_pid_to_mm(pid);
        if (!mm) { args->ret = -3; args->skip_origin = 1; return; }
        ret = wxshadow_do_set_reg(mm, arg3, (unsigned int)arg4, arg5);
        kfunc_mmput(mm);
        args->ret = ret;
        args->skip_origin = 1;
        break;

    case PR_WXSHADOW_DEL_BP:
        pid = (pid_t)arg2;
        mm = resolve_pid_to_mm(pid);
        if (!mm) { args->ret = -3; args->skip_origin = 1; return; }
        if (arg3 == 0) {
            wxshadow_teardown_pages_for_mm(mm, "del_all_bp");
            ret = 0;
        } else {
            ret = wxshadow_do_del_bp(mm, arg3);
        }
        kfunc_mmput(mm);
        args->ret = ret;
        args->skip_origin = 1;
        break;

    case PR_WXSHADOW_SET_TLB_MODE:
        if (arg2 > WX_TLB_MODE_FULL) {
            pr_err("wxshadow: [prctl] invalid TLB mode: %lu\n", arg2);
            args->ret = -22;
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
        args->ret = tlb_flush_mode;
        args->skip_origin = 1;
        break;

    case PR_WXSHADOW_PATCH:
        pid = (pid_t)arg2;
        mm = resolve_pid_to_mm(pid);
        if (!mm) { args->ret = -3; args->skip_origin = 1; return; }
        ret = wxshadow_do_patch(mm, arg3, (void __user *)arg4, arg5);
        kfunc_mmput(mm);
        args->ret = ret;
        args->skip_origin = 1;
        break;

    case PR_WXSHADOW_RELEASE:
        pid = (pid_t)arg2;
        mm = resolve_pid_to_mm(pid);
        if (!mm) { args->ret = -3; args->skip_origin = 1; return; }
        if (arg3 == 0) {
            wxshadow_teardown_pages_for_mm(mm, "release_all");
            ret = 0;
        } else {
            ret = wxshadow_do_release(mm, arg3);
        }
        kfunc_mmput(mm);
        args->ret = ret;
        args->skip_origin = 1;
        break;

    default:
        break;
    }
}
