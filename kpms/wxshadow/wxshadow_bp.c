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

static int require_tlb_flush_capability(const char *op)
{
    if (check_tlb_flush_capability() < 0) {
        pr_err("wxshadow: [%s] no TLB flush method available!\n", op);
        pr_err("wxshadow: [%s] need flush_tlb_page, __flush_tlb_range, or mm_context_id_offset\n",
               op);
        return -38;  /* ENOSYS */
    }

    if (!kfunc_flush_tlb_page && !kfunc___flush_tlb_range) {
        pr_info("wxshadow: [%s] using TLBI instruction with ASID (context_id_offset=0x%x)\n",
                op, mm_context_id_offset);
    }

    return 0;
}

static int prepare_shadow_target(void *mm, unsigned long addr,
                                 unsigned long page_addr, const char *op,
                                 void **out_vma)
{
    void *vma;
    int ret;

    vma = kfunc_find_vma(mm, addr);
    if (!vma || vma_start(vma) > addr) {
        pr_err("wxshadow: [%s] no vma for %lx\n", op, addr);
        return -1;
    }

    ret = wxshadow_try_split_pmd(mm, vma, page_addr);
    if (ret < 0) {
        pr_err("wxshadow: [%s] PMD split failed for %lx: %d\n",
               op, page_addr, ret);
        return ret;
    }

    *out_vma = vma;
    return 0;
}

static struct wxshadow_page *find_usable_shadow_page(void *mm,
                                                     unsigned long page_addr)
{
    struct wxshadow_page *page_info;
    bool usable;

    page_info = wxshadow_find_page(mm, page_addr);  /* caller ref if non-NULL */
    if (!page_info)
        return NULL;

    spin_lock(&global_lock);
    usable = !page_info->dead && page_info->shadow_page != NULL;
    spin_unlock(&global_lock);

    if (usable)
        return page_info;

    wxshadow_page_put(page_info);
    return NULL;
}

static int create_shadow_page_common(void *mm, unsigned long page_addr,
                                     const char *op,
                                     struct wxshadow_page **out_page_info,
                                     void **out_orig_kaddr)
{
    struct wxshadow_page *page_info;
    u64 *pte;
    unsigned long orig_pfn;
    unsigned long shadow_vaddr;

    page_info = wxshadow_create_page(mm, page_addr);
    if (!page_info) {
        pr_err("wxshadow: [%s] failed to create page structure\n", op);
        return -12;
    }

    pte = get_user_pte(mm, page_addr, NULL);
    if (!pte || !(*pte & PTE_VALID)) {
        pr_err("wxshadow: [%s] no pte for %lx\n", op, page_addr);
        goto err_fault;
    }

    orig_pfn = (*pte >> PAGE_SHIFT) & 0xFFFFFFFFFUL;
    page_info->pfn_original = orig_pfn;
    *out_orig_kaddr = pfn_to_kaddr(orig_pfn);
    if (!is_kva((unsigned long)*out_orig_kaddr)) {
        pr_err("wxshadow: [%s] invalid orig_kaddr %px for pfn %lx\n",
               op, *out_orig_kaddr, orig_pfn);
        goto err_fault;
    }

    shadow_vaddr = kfunc___get_free_pages(0xcc0, 0);
    if (!shadow_vaddr) {
        pr_err("wxshadow: [%s] failed to allocate shadow page\n", op);
        goto err_nomem;
    }

    page_info->pfn_shadow = kaddr_to_pfn(shadow_vaddr);
    page_info->shadow_page = (void *)shadow_vaddr;

    {
        unsigned long backup_vaddr = kfunc___get_free_pages(0xcc0, 0);
        if (!backup_vaddr) {
            pr_err("wxshadow: [%s] failed to allocate orig_backup page\n", op);
            goto err_nomem;
        }
        memcpy((void *)backup_vaddr, *out_orig_kaddr, PAGE_SIZE);
        page_info->orig_backup = (void *)backup_vaddr;
        page_info->pfn_orig_backup = kaddr_to_pfn(backup_vaddr);
    }

    *out_page_info = page_info;
    return 0;

err_fault:
    wxshadow_free_page(page_info);
    wxshadow_page_put(page_info);
    return -14;

err_nomem:
    wxshadow_free_page(page_info);
    wxshadow_page_put(page_info);
    return -12;
}

static int prepare_existing_shadow_page(struct wxshadow_page *page_info,
                                        unsigned long page_addr,
                                        const char *op,
                                        bool *out_needs_activation)
{
    bool busy;
    bool needs_activation;

    spin_lock(&global_lock);
    busy = page_info->release_pending ||
           page_info->state == WX_STATE_STEPPING;
    needs_activation = !page_info->dead &&
                       page_info->state != WX_STATE_SHADOW_X;
    spin_unlock(&global_lock);

    if (busy) {
        pr_err("wxshadow: [%s] page %lx busy with in-flight step/release\n",
               op, page_addr);
        return -16;  /* EBUSY */
    }

    if (out_needs_activation)
        *out_needs_activation = needs_activation;
    return 0;
}

static int acquire_shadow_page_for_write(void *mm, unsigned long addr,
                                         unsigned long page_addr,
                                         const char *op,
                                         void **out_vma,
                                         struct wxshadow_page **out_page_info,
                                         void **out_orig_kaddr,
                                         bool *out_is_new,
                                         bool *out_needs_activation)
{
    struct wxshadow_page *page_info;
    int ret;

    *out_page_info = NULL;
    *out_orig_kaddr = NULL;
    *out_is_new = false;
    if (out_needs_activation)
        *out_needs_activation = false;

    ret = prepare_shadow_target(mm, addr, page_addr, op, out_vma);
    if (ret < 0)
        return ret;

    page_info = find_usable_shadow_page(mm, page_addr);
    if (page_info) {
        ret = prepare_existing_shadow_page(page_info, page_addr, op,
                                           out_needs_activation);
        if (ret < 0) {
            wxshadow_page_put(page_info);
            return ret;
        }

        *out_page_info = page_info;
        return 0;
    }

    ret = create_shadow_page_common(mm, page_addr, op, out_page_info,
                                    out_orig_kaddr);
    if (ret < 0)
        return ret;

    *out_is_new = true;
    if (out_needs_activation)
        *out_needs_activation = true;
    return 0;
}

static void destroy_unactivated_shadow_page(struct wxshadow_page *page_info)
{
    if (!page_info)
        return;

    wxshadow_free_page(page_info);
    wxshadow_page_put(page_info);
}

static int activate_shadow_page(void *vma, unsigned long page_addr,
                                struct wxshadow_page *page_info)
{
    return wxshadow_page_activate_shadow(page_info, vma, page_addr);
}

static int ensure_bp_slot(struct wxshadow_page *page_info, unsigned long addr)
{
    int i;

    for (i = 0; i < page_info->nr_bps; i++) {
        if (page_info->bps[i].addr != addr)
            continue;

        page_info->bps[i].active = true;
        return i;
    }

    if (page_info->nr_bps >= WXSHADOW_MAX_BPS_PER_PAGE)
        return -28;  /* ENOSPC */

    i = page_info->nr_bps++;
    memset(&page_info->bps[i], 0, sizeof(page_info->bps[i]));
    page_info->bps[i].addr = addr;
    page_info->bps[i].active = true;
    return i;
}

enum wxshadow_shadow_flush_mode {
    WXSHADOW_SHADOW_FLUSH_CACHELINE = 0,
    WXSHADOW_SHADOW_FLUSH_PAGE,
};

static int copy_original_page_to_shadow(struct wxshadow_page *page_info,
                                        const void *orig_kaddr)
{
    if (!page_info || !page_info->shadow_page || !orig_kaddr)
        return -22;  /* EINVAL */

    memcpy(page_info->shadow_page, orig_kaddr, PAGE_SIZE);
    return 0;
}

static int write_shadow_bytes(struct wxshadow_page *page_info,
                              unsigned long page_addr, unsigned long offset,
                              const void *src, unsigned long len,
                              enum wxshadow_shadow_flush_mode flush_mode,
                              bool flush_icache)
{
    unsigned long shadow_vaddr;

    if (!page_info || !page_info->shadow_page || !src || len == 0 ||
        offset + len > PAGE_SIZE)
        return -22;  /* EINVAL */

    shadow_vaddr = (unsigned long)page_info->shadow_page;
    memcpy((void *)(shadow_vaddr + offset), src, len);

    if (flush_mode == WXSHADOW_SHADOW_FLUSH_PAGE) {
        wxshadow_flush_kern_dcache_area(shadow_vaddr, PAGE_SIZE);
    } else {
        wxshadow_flush_kern_dcache_area(shadow_vaddr + (offset & ~63UL), 64);
    }

    if (flush_icache)
        wxshadow_flush_icache_page(page_addr);

    return 0;
}

static int write_shadow_u32(struct wxshadow_page *page_info,
                            unsigned long page_addr, unsigned long offset,
                            u32 value,
                            enum wxshadow_shadow_flush_mode flush_mode,
                            bool flush_icache)
{
    return write_shadow_bytes(page_info, page_addr, offset, &value,
                              sizeof(value), flush_mode, flush_icache);
}

/* ========== Set breakpoint ========== */

int wxshadow_do_set_bp(void *mm, unsigned long addr)
{
    void *vma;
    struct wxshadow_page *page_info;
    void *orig_kaddr;
    unsigned long page_addr = addr & PAGE_MASK;
    unsigned long offset = addr & ~PAGE_MASK;
    bool is_new;
    int ret;
    int bp_idx;

    pr_info("wxshadow: [set_bp] addr=%lx\n", addr);

    ret = require_tlb_flush_capability("set_bp");
    if (ret < 0)
        return ret;

    ret = acquire_shadow_page_for_write(mm, addr, page_addr, "set_bp",
                                        &vma, &page_info, &orig_kaddr,
                                        &is_new, NULL);
    if (ret < 0)
        return ret;

    bp_idx = ensure_bp_slot(page_info, addr);
    if (bp_idx < 0) {
        pr_err("wxshadow: [set_bp] too many breakpoints on page %lx\n",
               page_addr);
        if (is_new)
            destroy_unactivated_shadow_page(page_info);
        else
            wxshadow_page_put(page_info);
        return bp_idx;
    }

    if (!is_new) {
        ret = write_shadow_u32(page_info, page_addr, offset,
                               WXSHADOW_BRK_INSN,
                               WXSHADOW_SHADOW_FLUSH_CACHELINE, true);
        if (ret < 0) {
            wxshadow_page_put(page_info);
            return ret;
        }
        pr_info("wxshadow: bp at %lx (existing page)\n", addr);
        wxshadow_page_put(page_info);  /* release caller ref */
        return 0;
    }

    /* Copy original to shadow and write BRK */
    ret = copy_original_page_to_shadow(page_info, orig_kaddr);
    if (ret < 0)
        goto err_free_page;
    ret = write_shadow_u32(page_info, page_addr, offset, WXSHADOW_BRK_INSN,
                           WXSHADOW_SHADOW_FLUSH_PAGE, false);
    if (ret < 0)
        goto err_free_page;

    ret = activate_shadow_page(vma, page_addr, page_info);
    if (ret == 0) {
        pr_info("wxshadow: bp at %lx orig_pfn=%lx shadow_pfn=%lx\n",
                addr, page_info->pfn_original, page_info->pfn_shadow);
        wxshadow_page_put(page_info);  /* release caller ref; page stays in list */
    } else {
        pr_err("wxshadow: [set_bp] switch failed\n");
        goto err_free_page;
    }

    return ret;

err_free_page:
    destroy_unactivated_shadow_page(page_info);
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
    void *vma, *orig_kaddr, *patch_data;
    bool is_new;
    bool needs_activation;
    int ret;

    pr_info("wxshadow: [patch] addr=%lx len=%lu\n", addr, len);

    if (len == 0 || offset + len > PAGE_SIZE) {
        pr_err("wxshadow: [patch] invalid len=%lu offset=%lu\n", len, offset);
        return -22;  /* EINVAL */
    }

    ret = require_tlb_flush_capability("patch");
    if (ret < 0)
        return ret;

    /* Read user buffer into kernel memory via PTE walk */
    patch_data = copy_from_user_via_pte(buf, len);
    if (!patch_data)
        return -14;  /* EFAULT */

    ret = acquire_shadow_page_for_write(mm, addr, page_addr, "patch",
                                        &vma, &page_info, &orig_kaddr,
                                        &is_new, &needs_activation);
    if (ret < 0)
        goto out_free;

    if (!is_new) {
        /* Safe: ref held, shadow freed only at refcount=0 */
        ret = write_shadow_bytes(page_info, page_addr, offset, patch_data, len,
                                 WXSHADOW_SHADOW_FLUSH_PAGE,
                                 !needs_activation);
        if (ret < 0) {
            wxshadow_page_put(page_info);
            goto out_free;
        }

        if (needs_activation) {
            ret = activate_shadow_page(vma, page_addr, page_info);
            if (ret < 0) {
                wxshadow_page_put(page_info);
                goto out_free;
            }
        }

        pr_info("wxshadow: [patch] existing shadow %lx+%lx (%lu bytes)\n",
                page_addr, offset, len);
        wxshadow_page_put(page_info);
        goto out_free;
    }

    /* Build shadow: original content + patch overlay */
    ret = copy_original_page_to_shadow(page_info, orig_kaddr);
    if (ret < 0)
        goto out_free_page;
    ret = write_shadow_bytes(page_info, page_addr, offset, patch_data, len,
                             WXSHADOW_SHADOW_FLUSH_PAGE, false);
    if (ret < 0)
        goto out_free_page;

    page_info->nr_bps = 0;

    ret = activate_shadow_page(vma, page_addr, page_info);
    if (ret == 0) {
        pr_info("wxshadow: [patch] new shadow %lx+%lx (%lu bytes) pfn %lx->%lx\n",
                page_addr, offset, len, page_info->pfn_original,
                page_info->pfn_shadow);
    } else {
        goto out_free_page;
    }

    wxshadow_page_put(page_info);  /* release caller ref; page stays in list */
    kfunc_kfree(patch_data);
    return 0;

out_free_page:
    destroy_unactivated_shadow_page(page_info);
out_free:
    kfunc_kfree(patch_data);
    return ret;
}

/* ========== Release: Release shadow page ========== */

int wxshadow_do_release(void *mm, unsigned long addr)
{
    struct wxshadow_page *page_info;
    unsigned long page_addr = addr & PAGE_MASK;
    int ret;

    pr_info("wxshadow: [release] addr=%lx\n", addr);

    page_info = wxshadow_find_page(mm, page_addr);
    if (!page_info) {
        pr_err("wxshadow: [release] page not found for %lx\n", addr);
        return -2;  /* ENOENT */
    }

    ret = wxshadow_teardown_page(page_info, "user release");
    wxshadow_page_put(page_info);
    return ret;
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
    int ret;
    void *orig_kaddr;
    u32 orig_insn;

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
        bool can_restore;

        spin_lock(&global_lock);
        can_restore = !page_info->dead && !page_info->release_pending &&
                      page_info->state != WX_STATE_STEPPING &&
                      page_info->shadow_page &&
                      page_info->pfn_original;
        spin_unlock(&global_lock);

        if (can_restore) {
            orig_kaddr = pfn_to_kaddr(page_info->pfn_original);
            if (!is_kva((unsigned long)orig_kaddr)) {
                pr_err("wxshadow: [del_bp] invalid orig_kaddr %px\n", orig_kaddr);
                wxshadow_page_put(page_info);
                return -14;
            }
            orig_insn = *(u32 *)((char *)orig_kaddr + offset);

            ret = write_shadow_u32(page_info, page_addr, offset, orig_insn,
                                   WXSHADOW_SHADOW_FLUSH_CACHELINE, true);
            if (ret < 0) {
                wxshadow_page_put(page_info);
                return ret;
            }
        }
        wxshadow_page_put(page_info);  /* release caller ref; page stays in list */
        return 0;
    }

    /* Last BP - unified teardown handles PTE restore, free, etc. */
    ret = wxshadow_teardown_page(page_info, "last bp removed");
    wxshadow_page_put(page_info);
    return ret;
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

    /* Only track wxshadow prctl calls for in-flight counting */
    if (option < PR_WXSHADOW_SET_BP || option > PR_WXSHADOW_RELEASE)
        return;

    WX_HANDLER_ENTER();

    /* Lazy scan mm->context.id offset on first wxshadow prctl call */
    if (mm_context_id_offset < 0)
        try_scan_mm_context_id_offset();

    switch (option) {
    case PR_WXSHADOW_SET_BP:
        pid = (pid_t)arg2;
        mm = resolve_pid_to_mm(pid);
        if (!mm) { args->ret = -3; args->skip_origin = 1; break; }
        ret = wxshadow_do_set_bp(mm, arg3);
        kfunc_mmput(mm);
        args->ret = ret;
        args->skip_origin = 1;
        break;

    case PR_WXSHADOW_SET_REG:
        pid = (pid_t)arg2;
        mm = resolve_pid_to_mm(pid);
        if (!mm) { args->ret = -3; args->skip_origin = 1; break; }
        ret = wxshadow_do_set_reg(mm, arg3, (unsigned int)arg4, arg5);
        kfunc_mmput(mm);
        args->ret = ret;
        args->skip_origin = 1;
        break;

    case PR_WXSHADOW_DEL_BP:
        pid = (pid_t)arg2;
        mm = resolve_pid_to_mm(pid);
        if (!mm) { args->ret = -3; args->skip_origin = 1; break; }
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
        if (!mm) { args->ret = -3; args->skip_origin = 1; break; }
        ret = wxshadow_do_patch(mm, arg3, (void __user *)arg4, arg5);
        kfunc_mmput(mm);
        args->ret = ret;
        args->skip_origin = 1;
        break;

    case PR_WXSHADOW_RELEASE:
        pid = (pid_t)arg2;
        mm = resolve_pid_to_mm(pid);
        if (!mm) { args->ret = -3; args->skip_origin = 1; break; }
        if (arg3 == 0) {
            ret = wxshadow_release_pages_for_mm(mm, "release_all");
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

    WX_HANDLER_EXIT();
}
