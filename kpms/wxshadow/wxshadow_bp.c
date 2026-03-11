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
    page_info->pte_original = *pte;
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
                                        bool *out_needs_activation,
                                        bool *out_needs_refresh)
{
    int i;

    for (i = 0; i < WXSHADOW_RELEASE_WAIT_LOOPS; i++) {
        bool busy;
        bool dead;
        bool needs_activation;
        bool needs_refresh;

        spin_lock(&global_lock);
        dead = page_info->dead;
        busy = page_info->release_pending ||
               page_info->logical_release_pending ||
               page_info->brk_in_flight > 0 ||
               page_info->state == WX_STATE_STEPPING;
        needs_activation = !dead &&
                           page_info->state != WX_STATE_SHADOW_X;
        needs_refresh = !dead &&
                        page_info->state == WX_STATE_DORMANT;
        spin_unlock(&global_lock);

        if (dead)
            return 1;

        if (!busy) {
            if (out_needs_activation)
                *out_needs_activation = needs_activation;
            if (out_needs_refresh)
                *out_needs_refresh = needs_refresh;
            return 0;
        }

        cpu_relax();
    }

    pr_err("wxshadow: [%s] page %lx busy with in-flight step/release\n",
           op, page_addr);
    return -16;  /* EBUSY */
}

static int refresh_dormant_shadow_page(struct wxshadow_page *page_info,
                                       void *mm, unsigned long page_addr,
                                       const char *op)
{
    u64 *pte;
    unsigned long orig_pfn;
    unsigned long shadow_vaddr;
    void *orig_kaddr;

    if (!page_info || !mm)
        return -22;

    wxshadow_page_pte_lock(page_info);

    spin_lock(&global_lock);
    if (page_info->dead || page_info->release_pending ||
        page_info->logical_release_pending ||
        page_info->state != WX_STATE_DORMANT ||
        !page_info->shadow_page) {
        spin_unlock(&global_lock);
        wxshadow_page_pte_unlock(page_info);
        return 0;
    }
    shadow_vaddr = (unsigned long)page_info->shadow_page;
    spin_unlock(&global_lock);

    pte = get_user_pte(mm, page_addr, NULL);
    if (!pte || !(*pte & PTE_VALID)) {
        pr_err("wxshadow: [%s] no pte while refreshing dormant page %lx\n",
               op, page_addr);
        wxshadow_page_pte_unlock(page_info);
        return -14;
    }

    orig_pfn = (*pte >> PAGE_SHIFT) & 0xFFFFFFFFFUL;
    orig_kaddr = pfn_to_kaddr(orig_pfn);
    if (!is_kva((unsigned long)orig_kaddr)) {
        pr_err("wxshadow: [%s] invalid orig_kaddr %px for dormant page %lx pfn %lx\n",
               op, orig_kaddr, page_addr, orig_pfn);
        wxshadow_page_pte_unlock(page_info);
        return -14;
    }

    memcpy((void *)shadow_vaddr, orig_kaddr, PAGE_SIZE);
    wxshadow_flush_kern_dcache_area(shadow_vaddr, PAGE_SIZE);

    spin_lock(&global_lock);
    if (!page_info->dead && page_info->state == WX_STATE_DORMANT) {
        page_info->pfn_original = orig_pfn;
        page_info->pte_original = *pte;
    }
    spin_unlock(&global_lock);

    wxshadow_page_pte_unlock(page_info);

    pr_info("wxshadow: [%s] refreshed dormant page %lx to pfn %lx\n",
            op, page_addr, orig_pfn);
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
    bool needs_refresh = false;
    int ret;

    *out_page_info = NULL;
    *out_orig_kaddr = NULL;
    *out_is_new = false;
    if (out_needs_activation)
        *out_needs_activation = false;

    ret = prepare_shadow_target(mm, addr, page_addr, op, out_vma);
    if (ret < 0)
        return ret;

    for (;;) {
        page_info = find_usable_shadow_page(mm, page_addr);
        if (!page_info)
            break;

        ret = prepare_existing_shadow_page(page_info, page_addr, op,
                                           out_needs_activation,
                                           &needs_refresh);
        if (ret > 0) {
            wxshadow_page_put(page_info);
            continue;
        }
        if (ret < 0) {
            wxshadow_page_put(page_info);
            return ret;
        }

        if (needs_refresh) {
            ret = refresh_dormant_shadow_page(page_info, mm, page_addr, op);
            if (ret < 0) {
                wxshadow_page_put(page_info);
                return ret;
            }
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

struct wxshadow_write_ctx {
    const char *op;
    void *vma;
    struct wxshadow_page *page_info;
    void *orig_kaddr;
    unsigned long page_addr;
    bool is_new;
    bool needs_activation;
};

static int wxshadow_acquire_write_ctx(void *mm, unsigned long addr,
                                      const char *op,
                                      struct wxshadow_write_ctx *ctx)
{
    int ret;

    if (!ctx)
        return -22;

    memset(ctx, 0, sizeof(*ctx));
    ctx->op = op;
    ctx->page_addr = addr & PAGE_MASK;

    ret = require_tlb_flush_capability(op);
    if (ret < 0)
        return ret;

    return acquire_shadow_page_for_write(mm, addr, ctx->page_addr, op,
                                         &ctx->vma, &ctx->page_info,
                                         &ctx->orig_kaddr, &ctx->is_new,
                                         &ctx->needs_activation);
}

static void wxshadow_put_write_ctx(struct wxshadow_write_ctx *ctx)
{
    if (!ctx || !ctx->page_info)
        return;

    wxshadow_page_put(ctx->page_info);
    ctx->page_info = NULL;
}

static void wxshadow_abort_write_ctx(struct wxshadow_write_ctx *ctx)
{
    if (!ctx || !ctx->page_info)
        return;

    if (ctx->is_new)
        destroy_unactivated_shadow_page(ctx->page_info);
    else
        wxshadow_page_put(ctx->page_info);
    ctx->page_info = NULL;
}

static int wxshadow_activate_write_ctx(struct wxshadow_write_ctx *ctx,
                                       bool force_activation)
{
    if (!ctx || !ctx->page_info)
        return -22;

    if (!force_activation && !ctx->needs_activation)
        return 0;

    return activate_shadow_page(ctx->vma, ctx->page_addr, ctx->page_info);
}

static u64 next_mod_serial_locked(struct wxshadow_page *page_info)
{
    page_info->next_mod_serial++;
    if (page_info->next_mod_serial == 0)
        page_info->next_mod_serial++;
    return page_info->next_mod_serial;
}

static int ensure_bp_slot(struct wxshadow_page *page_info, unsigned long addr)
{
    int i;
    int free_idx = -1;

    spin_lock(&global_lock);
    for (i = 0; i < page_info->nr_bps; i++) {
        if (page_info->bps[i].addr == addr) {
            if (!page_info->bps[i].active) {
                memset(&page_info->bps[i], 0, sizeof(page_info->bps[i]));
                page_info->bps[i].addr = addr;
            }
            page_info->bps[i].active = true;
            page_info->bps[i].serial = next_mod_serial_locked(page_info);
            spin_unlock(&global_lock);
            return i;
        }
        if (free_idx < 0 && !page_info->bps[i].active)
            free_idx = i;
    }

    if (free_idx < 0) {
        if (page_info->nr_bps >= WXSHADOW_MAX_BPS_PER_PAGE) {
            spin_unlock(&global_lock);
            return -28;  /* ENOSPC */
        }
        free_idx = page_info->nr_bps++;
    }

    memset(&page_info->bps[free_idx], 0, sizeof(page_info->bps[free_idx]));
    page_info->bps[free_idx].addr = addr;
    page_info->bps[free_idx].active = true;
    page_info->bps[free_idx].serial = next_mod_serial_locked(page_info);
    spin_unlock(&global_lock);
    return free_idx;
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

static int wxshadow_prepare_new_write_ctx(struct wxshadow_write_ctx *ctx)
{
    if (!ctx || !ctx->page_info || !ctx->is_new)
        return -22;

    return copy_original_page_to_shadow(ctx->page_info, ctx->orig_kaddr);
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

static int upsert_patch_record(struct wxshadow_page *page_info,
                               unsigned long offset, unsigned long len,
                               void *patch_data, void **out_old_data,
                               unsigned long *out_rebuild_len)
{
    int i;
    int free_idx = -1;
    int idx = -1;
    unsigned long rebuild_len = len;
    void *old_data = NULL;

    spin_lock(&global_lock);
    for (i = 0; i < page_info->nr_patches; i++) {
        if (page_info->patches[i].active &&
            page_info->patches[i].offset == offset) {
            idx = i;
            old_data = page_info->patches[i].data;
            if (page_info->patches[i].len > rebuild_len)
                rebuild_len = page_info->patches[i].len;
            break;
        }
        if (free_idx < 0 && !page_info->patches[i].active &&
            !page_info->patches[i].data) {
            free_idx = i;
        }
    }

    if (idx < 0) {
        if (free_idx < 0) {
            if (page_info->nr_patches >= WXSHADOW_MAX_PATCHES_PER_PAGE) {
                spin_unlock(&global_lock);
                return -28;  /* ENOSPC */
            }
            free_idx = page_info->nr_patches++;
        }
        idx = free_idx;
        memset(&page_info->patches[idx], 0, sizeof(page_info->patches[idx]));
    }

    page_info->patches[idx].offset = (u16)offset;
    page_info->patches[idx].len = (u16)len;
    page_info->patches[idx].active = true;
    page_info->patches[idx].data = patch_data;
    page_info->patches[idx].serial = next_mod_serial_locked(page_info);
    spin_unlock(&global_lock);

    if (out_old_data)
        *out_old_data = old_data;
    if (out_rebuild_len)
        *out_rebuild_len = rebuild_len;

    wxshadow_sync_page_tracking(page_info);
    return 0;
}

struct shadow_apply_op {
    u64 serial;
    unsigned long offset;
    unsigned long len;
    const void *data;
    bool is_bp;
};

static int wxshadow_rebuild_shadow_range(struct wxshadow_page *page_info,
                                         unsigned long offset,
                                         unsigned long len)
{
    struct shadow_apply_op ops[WXSHADOW_MAX_ACTIVE_MODS_PER_PAGE];
    unsigned long original_pfn;
    unsigned long shadow_vaddr;
    unsigned long page_addr;
    unsigned long range_end;
    const char *original_kaddr;
    int nr_ops = 0;
    int i;
    int j;

    if (!page_info)
        return -22;
    if (len == 0)
        return 0;
    if (offset >= PAGE_SIZE || offset + len > PAGE_SIZE)
        return -22;

    spin_lock(&global_lock);
    if (!page_info->shadow_page || !page_info->pfn_original) {
        spin_unlock(&global_lock);
        return -14;
    }

    original_pfn = page_info->pfn_original;
    shadow_vaddr = (unsigned long)page_info->shadow_page;
    page_addr = page_info->page_addr;
    range_end = offset + len;

    for (i = 0; i < page_info->nr_patches; i++) {
        struct wxshadow_patch *patch = &page_info->patches[i];
        unsigned long patch_end;

        if (!patch->active || !patch->data || patch->len == 0)
            continue;

        patch_end = patch->offset + patch->len;
        if (patch->offset >= range_end || patch_end <= offset)
            continue;

        ops[nr_ops].serial = patch->serial;
        ops[nr_ops].offset = patch->offset;
        ops[nr_ops].len = patch->len;
        ops[nr_ops].data = patch->data;
        ops[nr_ops].is_bp = false;
        nr_ops++;
    }

    for (i = 0; i < page_info->nr_bps; i++) {
        struct wxshadow_bp *bp = &page_info->bps[i];
        unsigned long bp_offset;
        unsigned long bp_end;

        if (!bp->active)
            continue;

        bp_offset = bp->addr & ~PAGE_MASK;
        bp_end = bp_offset + AARCH64_INSN_SIZE;
        if (bp_offset >= range_end || bp_end <= offset)
            continue;

        ops[nr_ops].serial = bp->serial;
        ops[nr_ops].offset = bp_offset;
        ops[nr_ops].len = AARCH64_INSN_SIZE;
        ops[nr_ops].data = NULL;
        ops[nr_ops].is_bp = true;
        nr_ops++;
    }
    spin_unlock(&global_lock);

    original_kaddr = (const char *)pfn_to_kaddr(original_pfn);
    if (!is_kva((unsigned long)original_kaddr))
        return -14;

    memcpy((void *)(shadow_vaddr + offset),
           original_kaddr + offset, len);

    for (i = 1; i < nr_ops; i++) {
        struct shadow_apply_op op = ops[i];

        for (j = i - 1; j >= 0 && ops[j].serial > op.serial; j--)
            ops[j + 1] = ops[j];
        ops[j + 1] = op;
    }

    for (i = 0; i < nr_ops; i++) {
        unsigned long apply_start = ops[i].offset;
        unsigned long apply_end = ops[i].offset + ops[i].len;
        const char *src;
        u32 brk_insn = WXSHADOW_BRK_INSN;

        if (apply_start < offset)
            apply_start = offset;
        if (apply_end > range_end)
            apply_end = range_end;
        if (apply_start >= apply_end)
            continue;

        if (ops[i].is_bp) {
            src = (const char *)&brk_insn;
        } else {
            src = (const char *)ops[i].data;
        }

        memcpy((void *)(shadow_vaddr + apply_start),
               src + (apply_start - ops[i].offset),
               apply_end - apply_start);
    }

    wxshadow_flush_kern_dcache_area(shadow_vaddr + offset, len);
    wxshadow_flush_icache_page(page_addr);
    return 0;
}

static bool wxshadow_page_has_active_mods_locked(struct wxshadow_page *page_info)
{
    int i;

    for (i = 0; i < page_info->nr_bps; i++) {
        if (page_info->bps[i].active)
            return true;
    }
    for (i = 0; i < page_info->nr_patches; i++) {
        if (page_info->patches[i].active)
            return true;
    }
    return false;
}

static void wxshadow_clear_logical_release_pending_locked(
    struct wxshadow_page *page_info)
{
    if (page_info && !page_info->dead)
        page_info->logical_release_pending = false;
}

static void wxshadow_clear_logical_release_pending(struct wxshadow_page *page_info)
{
    spin_lock(&global_lock);
    wxshadow_clear_logical_release_pending_locked(page_info);
    spin_unlock(&global_lock);
}

#define WXSHADOW_RELEASE_MATCH_BP    (1U << 0)
#define WXSHADOW_RELEASE_MATCH_PATCH (1U << 1)

static int wxshadow_wait_for_release_brk_handlers(struct wxshadow_page *page_info,
                                                  const char *reason)
{
    int i;

    if (!page_info)
        return -22;

    for (i = 0; i < WXSHADOW_RELEASE_WAIT_LOOPS; i++) {
        bool done;

        spin_lock(&global_lock);
        done = page_info->dead || page_info->brk_in_flight == 0;
        spin_unlock(&global_lock);

        if (done)
            return 0;

        cpu_relax();
    }

    pr_warn("wxshadow: [%s] timeout waiting for in-flight BRK handlers at addr=%lx\n",
            reason, page_info->page_addr);
    return -16;
}

static int wxshadow_release_mod_at_addr(struct wxshadow_page *page_info,
                                        unsigned long addr,
                                        unsigned int match_flags,
                                        const char *reason)
{
    void *free_patch_data[WXSHADOW_MAX_PATCHES_PER_PAGE];
    unsigned long offset = addr & ~PAGE_MASK;
    unsigned long range_start = PAGE_SIZE;
    unsigned long range_end = 0;
    bool wait_brk_handlers = false;
    bool matched = false;
    bool has_remaining;
    int nr_free = 0;
    int ret = 0;
    int i;

    if (!page_info)
        return -22;

retry:
    wxshadow_page_pte_lock(page_info);

    spin_lock(&global_lock);
    if (page_info->dead || !page_info->shadow_page) {
        spin_unlock(&global_lock);
        wxshadow_page_pte_unlock(page_info);
        return -ENODATA;
    }
    wait_brk_handlers = page_info->brk_in_flight > 0;
    if (page_info->release_pending || page_info->state == WX_STATE_STEPPING ||
        wait_brk_handlers || page_info->logical_release_pending) {
        spin_unlock(&global_lock);
        wxshadow_page_pte_unlock(page_info);
        if (wait_brk_handlers) {
            ret = wxshadow_wait_for_release_brk_handlers(page_info, reason);
            if (ret < 0)
                return ret;
        } else {
            cpu_relax();
        }
        goto retry;
    }
    page_info->logical_release_pending = true;
    if (page_info->dead || !page_info->shadow_page) {
        spin_unlock(&global_lock);
        wxshadow_page_pte_unlock(page_info);
        return -ENODATA;
    }
    if (page_info->release_pending || page_info->state == WX_STATE_STEPPING ||
        page_info->brk_in_flight > 0) {
        wxshadow_clear_logical_release_pending_locked(page_info);
        spin_unlock(&global_lock);
        wxshadow_page_pte_unlock(page_info);
        cpu_relax();
        goto retry;
    }

    if (match_flags & WXSHADOW_RELEASE_MATCH_BP) {
        for (i = 0; i < page_info->nr_bps; i++) {
            struct wxshadow_bp *bp = &page_info->bps[i];

            if (!bp->active || bp->addr != addr)
                continue;

            bp->active = false;
            bp->serial = 0;
            memset(bp->reg_mods, 0, sizeof(bp->reg_mods));
            bp->nr_reg_mods = 0;
            if (range_start > offset)
                range_start = offset;
            if (range_end < offset + AARCH64_INSN_SIZE)
                range_end = offset + AARCH64_INSN_SIZE;
            matched = true;
        }
    }

    if (match_flags & WXSHADOW_RELEASE_MATCH_PATCH) {
        for (i = 0; i < page_info->nr_patches; i++) {
            struct wxshadow_patch *patch = &page_info->patches[i];

            if (!patch->active || patch->offset != offset)
                continue;

            if (patch->data)
                free_patch_data[nr_free++] = patch->data;
            if (range_start > patch->offset)
                range_start = patch->offset;
            if (range_end < patch->offset + patch->len)
                range_end = patch->offset + patch->len;
            patch->active = false;
            patch->serial = 0;
            patch->len = 0;
            patch->data = NULL;
            matched = true;
        }
    }

    has_remaining = wxshadow_page_has_active_mods_locked(page_info);
    spin_unlock(&global_lock);

    if (!matched) {
        pr_err("wxshadow: [release] no matching modification at addr=%lx (page=%lx offset=%lx)\n",
               addr, page_info->page_addr, offset);
        wxshadow_clear_logical_release_pending(page_info);
        wxshadow_page_pte_unlock(page_info);
        return -ENODATA;
    }

    wxshadow_sync_page_tracking(page_info);

    if (range_start < range_end) {
        ret = wxshadow_rebuild_shadow_range(page_info, range_start,
                                            range_end - range_start);
    }
    wxshadow_clear_logical_release_pending(page_info);

    wxshadow_page_pte_unlock(page_info);

    for (i = 0; i < nr_free; i++)
        kfunc_kfree(free_patch_data[i]);

    if (ret < 0) {
        /* Rebuild failed after metadata changed; retire the page instead of
         * leaving a stale shadow mapping visible to future execution. */
        (void)wxshadow_teardown_page(page_info, reason);
        return ret;
    }

    if (!has_remaining) {
        ret = wxshadow_teardown_page(page_info, reason);
        if (ret < 0)
            return ret;
    }

    return 0;
}

/* ========== Set breakpoint ========== */

int wxshadow_do_set_bp(void *mm, unsigned long addr)
{
    struct wxshadow_write_ctx ctx;
    unsigned long offset = addr & ~PAGE_MASK;
    int ret;
    int bp_idx;

    pr_info("wxshadow: [set_bp] addr=%lx\n", addr);

    ret = wxshadow_acquire_write_ctx(mm, addr, "set_bp", &ctx);
    if (ret < 0)
        return ret;

    bp_idx = ensure_bp_slot(ctx.page_info, addr);
    if (bp_idx < 0) {
        pr_err("wxshadow: [set_bp] too many breakpoints on page %lx\n",
               ctx.page_addr);
        wxshadow_abort_write_ctx(&ctx);
        return bp_idx;
    }

    if (!ctx.is_new) {
        ret = write_shadow_u32(ctx.page_info, ctx.page_addr, offset,
                               WXSHADOW_BRK_INSN,
                               WXSHADOW_SHADOW_FLUSH_CACHELINE, true);
        if (ret < 0)
            goto out_abort;
        wxshadow_mark_bp_dirty(ctx.page_info, offset);
        ret = wxshadow_activate_write_ctx(&ctx, false);
        if (ret < 0)
            goto out_abort;
        pr_info("wxshadow: bp at %lx (existing page)\n", addr);
        wxshadow_put_write_ctx(&ctx);
        return 0;
    }

    /* Copy original to shadow and write BRK */
    ret = wxshadow_prepare_new_write_ctx(&ctx);
    if (ret < 0)
        goto out_abort;
    ret = write_shadow_u32(ctx.page_info, ctx.page_addr, offset,
                           WXSHADOW_BRK_INSN,
                           WXSHADOW_SHADOW_FLUSH_PAGE, false);
    if (ret < 0)
        goto out_abort;
    wxshadow_mark_bp_dirty(ctx.page_info, offset);

    ret = wxshadow_activate_write_ctx(&ctx, true);
    if (ret == 0) {
        pr_info("wxshadow: bp at %lx orig_pfn=%lx shadow_pfn=%lx\n",
                addr, ctx.page_info->pfn_original, ctx.page_info->pfn_shadow);
        wxshadow_put_write_ctx(&ctx);
    } else {
        pr_err("wxshadow: [set_bp] switch failed\n");
        goto out_abort;
    }

    return ret;

out_abort:
    wxshadow_abort_write_ctx(&ctx);
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
    struct wxshadow_write_ctx ctx;
    unsigned long offset = addr & ~PAGE_MASK;
    void *patch_data;
    void *old_patch_data = NULL;
    unsigned long rebuild_len = len;
    int ret;

    pr_info("wxshadow: [patch] addr=%lx len=%lu\n", addr, len);

    if (len == 0 || offset + len > PAGE_SIZE) {
        pr_err("wxshadow: [patch] invalid len=%lu offset=%lu\n", len, offset);
        return -22;  /* EINVAL */
    }

    /* Read user buffer into kernel memory via PTE walk */
    patch_data = copy_from_user_via_pte(buf, len);
    if (!patch_data)
        return -14;  /* EFAULT */

    ret = wxshadow_acquire_write_ctx(mm, addr, "patch", &ctx);
    if (ret < 0)
        goto out_free;

    if (!ctx.is_new) {
        ret = upsert_patch_record(ctx.page_info, offset, len, patch_data,
                                  &old_patch_data, &rebuild_len);
        if (ret < 0) {
            wxshadow_put_write_ctx(&ctx);
            goto out_free;
        }
        patch_data = NULL;  /* ownership moved to page record */

        ret = wxshadow_rebuild_shadow_range(ctx.page_info, offset, rebuild_len);
        if (ret < 0) {
            wxshadow_put_write_ctx(&ctx);
            goto out_free;
        }

        ret = wxshadow_activate_write_ctx(&ctx, false);
        if (ret < 0) {
            wxshadow_put_write_ctx(&ctx);
            goto out_free;
        }

        if (old_patch_data) {
            kfunc_kfree(old_patch_data);
            old_patch_data = NULL;
        }
        pr_info("wxshadow: [patch] existing shadow %lx+%lx (%lu bytes)\n",
                ctx.page_addr, offset, len);
        wxshadow_put_write_ctx(&ctx);
        goto out_free;
    }

    /* Build shadow: original content + patch overlay */
    ret = wxshadow_prepare_new_write_ctx(&ctx);
    if (ret < 0)
        goto out_free_page;
    ret = upsert_patch_record(ctx.page_info, offset, len, patch_data, NULL, NULL);
    if (ret < 0)
        goto out_free_page;
    patch_data = NULL;  /* ownership moved to page record */

    ret = wxshadow_rebuild_shadow_range(ctx.page_info, offset, len);
    if (ret < 0)
        goto out_free_page;

    ctx.page_info->nr_bps = 0;

    ret = wxshadow_activate_write_ctx(&ctx, true);
    if (ret == 0) {
        pr_info("wxshadow: [patch] new shadow %lx+%lx (%lu bytes) pfn %lx->%lx\n",
                ctx.page_addr, offset, len, ctx.page_info->pfn_original,
                ctx.page_info->pfn_shadow);
    } else {
        goto out_free_page;
    }

    wxshadow_put_write_ctx(&ctx);
    kfunc_kfree(patch_data);
    return 0;

out_free_page:
    wxshadow_abort_write_ctx(&ctx);
out_free:
    if (old_patch_data)
        kfunc_kfree(old_patch_data);
    kfunc_kfree(patch_data);
    return ret;
}

/* ========== Release: Release shadow page ========== */

int wxshadow_do_release(void *mm, unsigned long addr)
{
    struct wxshadow_page *page_info;
    int ret;

    pr_info("wxshadow: [release] addr=%lx\n", addr);

    page_info = wxshadow_find_page(mm, addr);
    if (!page_info) {
        pr_err("wxshadow: [release] no shadow page for addr=%lx (page=%lx)\n",
               addr, addr & PAGE_MASK);
        return -ENODATA;
    }

    ret = wxshadow_release_mod_at_addr(page_info, addr,
                                       WXSHADOW_RELEASE_MATCH_BP |
                                       WXSHADOW_RELEASE_MATCH_PATCH,
                                       "user release");
    wxshadow_page_put(page_info);
    return ret;
}

/* ========== Delete breakpoint ========== */

int wxshadow_do_del_bp(void *mm, unsigned long addr)
{
    struct wxshadow_page *page_info;
    int ret;

    page_info = wxshadow_find_page(mm, addr);  /* caller ref */
    if (!page_info)
        return -2;

    pr_info("wxshadow: del bp at %lx\n", addr);
    ret = wxshadow_release_mod_at_addr(page_info, addr,
                                       WXSHADOW_RELEASE_MATCH_BP,
                                       "last bp removed");
    if (ret == -ENODATA)
        ret = -2;
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
            ret = wxshadow_release_pages_for_mm(mm, "del_all_bp");
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
