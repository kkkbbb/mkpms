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
void (*kfunc_kick_all_cpus_sync)(void);

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

/* fork protection hooks */
void *kfunc_dup_mmap = NULL;
void *kfunc_uprobe_dup_mmap = NULL;
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
    unsigned long shadow_vaddr = 0;
    void *patch_data[WXSHADOW_MAX_PATCHES_PER_PAGE];
    int nr_patch_data = 0;
    int i;

    spin_lock(&global_lock);
    should_free = (--page->refcount == 0);
    if (should_free) {
        if (page->shadow_page) {
            shadow_vaddr = (unsigned long)page->shadow_page;
            page->shadow_page = NULL;
        }
        for (i = 0; i < page->nr_patches; i++) {
            if (!page->patches[i].data)
                continue;
            patch_data[nr_patch_data++] = page->patches[i].data;
            page->patches[i].data = NULL;
        }
    }
    spin_unlock(&global_lock);

    if (should_free) {
        for (i = 0; i < nr_patch_data; i++)
            kfunc_kfree(patch_data[i]);
        if (shadow_vaddr)
            kfunc_free_pages(shadow_vaddr, 0);
        kfunc_kfree(page);
    }
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
    page->refcount = 2;            /* list ref + caller ref */
    page->dead = false;
    atomic_set(&page->pte_lock, 0);
    INIT_LIST_HEAD(&page->list);

    spin_lock(&global_lock);
    list_add(&page->list, &page_list);
    spin_unlock(&global_lock);

    pr_info("wxshadow: created page for mm=%px addr=%lx\n", mm, page_addr);
    return page;
}

/*
 * Free a page structure and remove from list.
 * Marks the page dead and releases the list's reference.
 * Caller must separately release its own ref via wxshadow_page_put().
 * Shadow page memory is freed when the last ref drops.
 */
void wxshadow_free_page(struct wxshadow_page *page)
{
    if (!page)
        return;

    spin_lock(&global_lock);
    page->dead = true;
    list_del_init(&page->list);
    spin_unlock(&global_lock);

    /* Release the list's ref.  When refcount reaches 0, page_put
     * frees shadow_page and the struct itself. */
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

static void wxshadow_bitmap_set_range(unsigned long *bitmap,
                                      unsigned long offset,
                                      unsigned long len);

static void wxshadow_trim_inactive_tail_locked(struct wxshadow_page *page)
{
    while (page->nr_bps > 0 && !page->bps[page->nr_bps - 1].active)
        page->nr_bps--;

    while (page->nr_patches > 0 &&
           !page->patches[page->nr_patches - 1].active &&
           !page->patches[page->nr_patches - 1].data)
        page->nr_patches--;
}

static void wxshadow_rebuild_dirty_tracking_locked(struct wxshadow_page *page)
{
    int i;

    if (!page)
        return;

    memset(page->bp_dirty, 0, sizeof(page->bp_dirty));
    memset(page->patch_dirty, 0, sizeof(page->patch_dirty));

    for (i = 0; i < page->nr_bps; i++) {
        struct wxshadow_bp *bp = &page->bps[i];

        if (!bp->active)
            continue;
        wxshadow_bitmap_set_range(page->bp_dirty,
                                  bp->addr & ~PAGE_MASK,
                                  AARCH64_INSN_SIZE);
    }

    for (i = 0; i < page->nr_patches; i++) {
        struct wxshadow_patch *patch = &page->patches[i];

        if (!patch->active || patch->len == 0)
            continue;
        wxshadow_bitmap_set_range(page->patch_dirty,
                                  patch->offset, patch->len);
    }
}

static void wxshadow_bitmap_set_range(unsigned long *bitmap,
                                      unsigned long offset,
                                      unsigned long len)
{
    unsigned long i;

    if (!bitmap || offset >= PAGE_SIZE || len == 0)
        return;

    if (offset + len > PAGE_SIZE)
        len = PAGE_SIZE - offset;

    for (i = offset; i < offset + len; i++) {
        unsigned long word = i / WXSHADOW_DIRTY_WORD_BITS;
        unsigned long bit = i % WXSHADOW_DIRTY_WORD_BITS;
        bitmap[word] |= (1UL << bit);
    }
}

static void wxshadow_bitmap_clear_range(unsigned long *bitmap,
                                        unsigned long offset,
                                        unsigned long len)
{
    unsigned long i;

    if (!bitmap || offset >= PAGE_SIZE || len == 0)
        return;

    if (offset + len > PAGE_SIZE)
        len = PAGE_SIZE - offset;

    for (i = offset; i < offset + len; i++) {
        unsigned long word = i / WXSHADOW_DIRTY_WORD_BITS;
        unsigned long bit = i % WXSHADOW_DIRTY_WORD_BITS;
        bitmap[word] &= ~(1UL << bit);
    }
}

static bool wxshadow_bitmap_test(const unsigned long *bitmap,
                                 unsigned long offset)
{
    unsigned long word;
    unsigned long bit;

    if (!bitmap || offset >= PAGE_SIZE)
        return false;

    word = offset / WXSHADOW_DIRTY_WORD_BITS;
    bit = offset % WXSHADOW_DIRTY_WORD_BITS;
    return !!(bitmap[word] & (1UL << bit));
}

static bool wxshadow_bitmap_any(const unsigned long *bitmap)
{
    unsigned long i;

    if (!bitmap)
        return false;

    for (i = 0; i < WXSHADOW_DIRTY_BITMAP_WORDS; i++) {
        if (bitmap[i])
            return true;
    }
    return false;
}

void wxshadow_mark_patch_dirty(struct wxshadow_page *page, unsigned long offset,
                               unsigned long len)
{
    if (!page)
        return;

    (void)offset;
    (void)len;

    spin_lock(&global_lock);
    wxshadow_rebuild_dirty_tracking_locked(page);
    spin_unlock(&global_lock);
}

void wxshadow_mark_bp_dirty(struct wxshadow_page *page, unsigned long offset)
{
    if (!page)
        return;

    (void)offset;

    spin_lock(&global_lock);
    wxshadow_rebuild_dirty_tracking_locked(page);
    spin_unlock(&global_lock);
}

void wxshadow_clear_bp_dirty(struct wxshadow_page *page, unsigned long offset)
{
    if (!page)
        return;

    (void)offset;

    spin_lock(&global_lock);
    wxshadow_rebuild_dirty_tracking_locked(page);
    spin_unlock(&global_lock);
}

void wxshadow_sync_page_tracking(struct wxshadow_page *page)
{
    if (!page)
        return;

    spin_lock(&global_lock);
    wxshadow_trim_inactive_tail_locked(page);
    wxshadow_rebuild_dirty_tracking_locked(page);
    spin_unlock(&global_lock);
}

bool wxshadow_page_has_patch_dirty(struct wxshadow_page *page)
{
    bool has_dirty;

    if (!page)
        return false;

    spin_lock(&global_lock);
    has_dirty = wxshadow_bitmap_any(page->patch_dirty);
    spin_unlock(&global_lock);
    return has_dirty;
}

void wxshadow_clear_page_tracking(struct wxshadow_page *page)
{
    void *patch_data[WXSHADOW_MAX_PATCHES_PER_PAGE];
    int nr_patch_data = 0;
    int i;

    if (!page)
        return;

    spin_lock(&global_lock);
    for (i = 0; i < page->nr_patches; i++) {
        if (!page->patches[i].data)
            continue;
        patch_data[nr_patch_data++] = page->patches[i].data;
        page->patches[i].data = NULL;
    }
    page->nr_bps = 0;
    page->nr_patches = 0;
    page->next_mod_serial = 0;
    memset(page->bps, 0, sizeof(page->bps));
    memset(page->patches, 0, sizeof(page->patches));
    memset(page->bp_dirty, 0, sizeof(page->bp_dirty));
    memset(page->patch_dirty, 0, sizeof(page->patch_dirty));
    spin_unlock(&global_lock);

    for (i = 0; i < nr_patch_data; i++)
        kfunc_kfree(patch_data[i]);
}

int wxshadow_restore_shadow_ranges(struct wxshadow_page *page)
{
    unsigned long bp_dirty[WXSHADOW_DIRTY_BITMAP_WORDS];
    unsigned long patch_dirty[WXSHADOW_DIRTY_BITMAP_WORDS];
    unsigned long original_pfn;
    unsigned long shadow_vaddr;
    unsigned long start;
    unsigned long end;
    unsigned long restored = 0;
    unsigned long page_addr;
    const char *original_kaddr;

    if (!page)
        return -22;

    spin_lock(&global_lock);
    if (!page->shadow_page || !page->pfn_original) {
        spin_unlock(&global_lock);
        return -14;
    }
    memcpy(bp_dirty, page->bp_dirty, sizeof(bp_dirty));
    memcpy(patch_dirty, page->patch_dirty, sizeof(patch_dirty));
    original_pfn = page->pfn_original;
    shadow_vaddr = (unsigned long)page->shadow_page;
    page_addr = page->page_addr;
    spin_unlock(&global_lock);

    original_kaddr = (const char *)pfn_to_kaddr(original_pfn);
    if (!is_kva((unsigned long)original_kaddr))
        return -14;

    start = 0;
    while (start < PAGE_SIZE) {
        bool dirty =
            wxshadow_bitmap_test(bp_dirty, start) ||
            wxshadow_bitmap_test(patch_dirty, start);

        if (!dirty) {
            start++;
            continue;
        }

        end = start + 1;
        while (end < PAGE_SIZE) {
            bool more_dirty =
                wxshadow_bitmap_test(bp_dirty, end) ||
                wxshadow_bitmap_test(patch_dirty, end);
            if (!more_dirty)
                break;
            end++;
        }

        memcpy((void *)(shadow_vaddr + start),
               original_kaddr + start,
               end - start);
        wxshadow_flush_kern_dcache_area(shadow_vaddr + start, end - start);
        restored += end - start;
        start = end;
    }

    if (restored)
        wxshadow_flush_icache_page(page_addr);

    pr_info("wxshadow: [logical_release] restored %lu bytes at addr=%lx\n",
            restored, page_addr);
    return 0;
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
            page_info->state == WX_STATE_SHADOW_X ||
            page_info->state == WX_STATE_DORMANT) {
            return 1;
        }
    }

    pr_info("wxshadow: validate_mapping: PFN mismatch for addr %lx: "
            "current=%lx, orig=%lx, shadow=%lx, state=%d\n",
            page_addr, current_pfn, page_info->pfn_original,
            page_info->pfn_shadow, page_info->state);
    return 0;
}

static int wxshadow_wait_for_logical_release(struct wxshadow_page *page,
                                             const char *reason)
{
    int i;

    for (i = 0; i < WXSHADOW_RELEASE_WAIT_LOOPS; i++) {
        bool done;

        spin_lock(&global_lock);
        done = page->dead ||
               (!page->logical_release_pending &&
                page->state == WX_STATE_DORMANT);
        spin_unlock(&global_lock);

        if (done)
            return 0;

        cpu_relax();
    }

    pr_warn("wxshadow: [logical_release] timeout waiting for step completion at addr=%lx during %s\n",
            page->page_addr, reason);
    return -16;
}

static int wxshadow_wait_for_brk_handlers(struct wxshadow_page *page,
                                          const char *reason)
{
    int i;

    for (i = 0; i < WXSHADOW_RELEASE_WAIT_LOOPS; i++) {
        bool done;

        spin_lock(&global_lock);
        done = page->dead || page->brk_in_flight == 0;
        spin_unlock(&global_lock);

        if (done)
            return 0;

        cpu_relax();
    }

    pr_warn("wxshadow: [%s] timeout waiting for in-flight BRK handlers at addr=%lx\n",
            reason, page->page_addr);
    return -16;
}

void wxshadow_sync_shadow_exec_zero(struct wxshadow_page *page,
                                    const char *reason)
{
    if (!kfunc_kick_all_cpus_sync) {
        pr_err("wxshadow: [%s] kick_all_cpus_sync unavailable at addr=%lx\n",
               reason, page ? page->page_addr : 0UL);
        return;
    }

    kfunc_kick_all_cpus_sync();
}

static void wxshadow_clear_logical_release_pending_locked(
    struct wxshadow_page *page)
{
    if (page && !page->dead)
        page->logical_release_pending = false;
}

static void wxshadow_clear_logical_release_pending(struct wxshadow_page *page)
{
    spin_lock(&global_lock);
    wxshadow_clear_logical_release_pending_locked(page);
    spin_unlock(&global_lock);
}

static int wxshadow_release_page_to_clean_shadow(struct wxshadow_page *page,
                                                 const char *reason)
{
    void *mm;
    void *vma;
    u64 probe;
    int state;
    int ret;

    if (!page)
        return 0;

retry:
    wxshadow_page_pte_lock(page);

    spin_lock(&global_lock);
    if (page->dead) {
        spin_unlock(&global_lock);
        wxshadow_page_pte_unlock(page);
        return 0;
    }

    if (page->release_pending) {
        spin_unlock(&global_lock);
        wxshadow_page_pte_unlock(page);
        return -16;
    }

    if (page->brk_in_flight > 0) {
        spin_unlock(&global_lock);
        wxshadow_page_pte_unlock(page);
        ret = wxshadow_wait_for_brk_handlers(page, reason);
        if (ret < 0)
            return ret;
        goto retry;
    }

    if (page->logical_release_pending) {
        spin_unlock(&global_lock);
        wxshadow_page_pte_unlock(page);
        cpu_relax();
        goto retry;
    }

    state = page->state;
    page->logical_release_pending = true;
    spin_unlock(&global_lock);

    if (state != WX_STATE_DORMANT && state != WX_STATE_NONE) {
        mm = page->mm;
        if (!mm || !page->pfn_original || !kfunc_find_vma) {
            ret = -14;
            goto out_fail_locked;
        }

        if (!is_kva((unsigned long)mm) ||
            !safe_read_u64((unsigned long)mm, &probe)) {
            ret = -14;
            goto out_fail_locked;
        }

        vma = kfunc_find_vma(mm, page->page_addr);
        if (!vma || vma_start(vma) > page->page_addr) {
            ret = -14;
            goto out_fail_locked;
        }

        ret = wxshadow_page_enter_dormant_locked(page, vma, page->page_addr);
        if (ret < 0)
            goto out_fail_locked;
    }

    wxshadow_page_pte_unlock(page);

    wxshadow_sync_shadow_exec_zero(page, reason);

    ret = wxshadow_wait_for_brk_handlers(page, reason);
    if (ret < 0)
        goto out_fail_unlocked;

    wxshadow_page_pte_lock(page);

    spin_lock(&global_lock);
    if (page->dead) {
        spin_unlock(&global_lock);
        wxshadow_page_pte_unlock(page);
        return 0;
    }
    if (page->release_pending || page->brk_in_flight > 0 ||
        page->state == WX_STATE_STEPPING) {
        wxshadow_clear_logical_release_pending_locked(page);
        spin_unlock(&global_lock);
        wxshadow_page_pte_unlock(page);
        cpu_relax();
        goto retry;
    }
    spin_unlock(&global_lock);

    ret = wxshadow_restore_shadow_ranges(page);
    if (ret < 0) {
        goto out_fail_locked;
    }

    wxshadow_clear_page_tracking(page);
    spin_lock(&global_lock);
    wxshadow_clear_logical_release_pending_locked(page);
    spin_unlock(&global_lock);
    wxshadow_page_pte_unlock(page);

    pr_info("wxshadow: [release_clean] %s: addr=%lx mapping retained\n",
            reason, page->page_addr);
    return 0;

out_fail_locked:
    spin_lock(&global_lock);
    wxshadow_clear_logical_release_pending_locked(page);
    spin_unlock(&global_lock);
    wxshadow_page_pte_unlock(page);
    pr_warn("wxshadow: [release_clean] %s failed for addr=%lx: %d\n",
            reason, page->page_addr, ret);
    return ret;

out_fail_unlocked:
    wxshadow_clear_logical_release_pending(page);
    pr_warn("wxshadow: [release_clean] %s failed while draining BRK handlers for addr=%lx: %d\n",
            reason, page->page_addr, ret);
    return ret;
}

int wxshadow_release_page_logically(struct wxshadow_page *page,
                                    const char *reason)
{
    void *mm;
    void *vma;
    u64 probe;
    int state;
    int ret;

    if (!page)
        return 0;

retry:
    wxshadow_page_pte_lock(page);

    spin_lock(&global_lock);
    if (page->dead) {
        spin_unlock(&global_lock);
        wxshadow_page_pte_unlock(page);
        return 0;
    }

    if (page->brk_in_flight > 0) {
        spin_unlock(&global_lock);
        wxshadow_page_pte_unlock(page);
        ret = wxshadow_wait_for_brk_handlers(page, reason);
        if (ret < 0)
            return ret;
        goto retry;
    }

    state = page->state;
    if (state == WX_STATE_DORMANT || state == WX_STATE_NONE) {
        wxshadow_clear_logical_release_pending_locked(page);
        spin_unlock(&global_lock);
        wxshadow_clear_page_tracking(page);
        wxshadow_page_pte_unlock(page);
        return 0;
    }

    page->logical_release_pending = true;
    if (state == WX_STATE_STEPPING &&
        page->stepping_task && page->stepping_task != current) {
        spin_unlock(&global_lock);

        ret = wxshadow_restore_shadow_ranges(page);
        if (ret == 0)
            wxshadow_clear_page_tracking(page);
        else {
            wxshadow_clear_logical_release_pending(page);
        }

        wxshadow_page_pte_unlock(page);
        if (ret < 0)
            return ret;

        pr_info("wxshadow: [logical_release] %s: addr=%lx state=%d pending until step completes\n",
                reason, page->page_addr, state);
        return wxshadow_wait_for_logical_release(page, reason);
    }
    spin_unlock(&global_lock);

    ret = wxshadow_restore_shadow_ranges(page);
    if (ret < 0)
        goto out_fail;

    mm = page->mm;
    if (!mm || !page->pfn_original || !kfunc_find_vma) {
        ret = -14;
        goto out_fail;
    }

    if (!is_kva((unsigned long)mm) ||
        !safe_read_u64((unsigned long)mm, &probe)) {
        ret = -14;
        goto out_fail;
    }

    vma = kfunc_find_vma(mm, page->page_addr);
    if (!vma || vma_start(vma) > page->page_addr) {
        ret = -14;
        goto out_fail;
    }

    ret = wxshadow_page_enter_dormant_locked(page, vma, page->page_addr);
    if (ret < 0)
        goto out_fail;

    wxshadow_clear_page_tracking(page);

    spin_lock(&global_lock);
    wxshadow_clear_logical_release_pending_locked(page);
    spin_unlock(&global_lock);

    pr_info("wxshadow: [logical_release] %s: addr=%lx state=%d -> DORMANT\n",
            reason, page->page_addr, state);
    wxshadow_page_pte_unlock(page);
    return 0;

out_fail:
    wxshadow_clear_logical_release_pending(page);
    wxshadow_page_pte_unlock(page);
    pr_warn("wxshadow: [logical_release] %s failed for addr=%lx: %d\n",
            reason, page->page_addr, ret);
    return ret;
}

static int wxshadow_wait_for_teardown(struct wxshadow_page *page,
                                      const char *reason)
{
    int i;

    for (i = 0; i < WXSHADOW_RELEASE_WAIT_LOOPS; i++) {
        bool done;

        spin_lock(&global_lock);
        done = page->dead;
        spin_unlock(&global_lock);

        if (done)
            return 0;

        cpu_relax();
    }

    pr_warn("wxshadow: [teardown] timeout waiting for step completion at addr=%lx during %s\n",
            page->page_addr, reason);
    return -16;  /* EBUSY */
}

/*
 * If teardown cannot actively restore the original PTE, only finalize when
 * the userspace mapping is already gone or no longer points at our private
 * shadow PFNs.
 */
static bool wxshadow_can_finalize_failed_teardown(struct wxshadow_page *page)
{
    void *mm;
    u64 probe;
    u64 *ptep;
    u64 pte_val;
    unsigned long current_pfn;

    if (!page)
        return false;

    if (!page->pfn_shadow)
        return true;

    mm = page->mm;
    if (!mm || !is_kva((unsigned long)mm) ||
        !safe_read_u64((unsigned long)mm, &probe))
        return false;

    ptep = get_user_pte(mm, page->page_addr, NULL);
    if (!ptep)
        return true;

    pte_val = *ptep;
    if (!(pte_val & PTE_VALID))
        return true;

    current_pfn = (pte_val & 0x0000FFFFFFFFF000UL) >> PAGE_SHIFT;
    if (page->pfn_shadow && current_pfn == page->pfn_shadow) {
        pr_err("wxshadow: [teardown] addr=%lx still mapped to private pfn=%lx after restore failure\n",
               page->page_addr, current_pfn);
        return false;
    }

    return true;
}

/*
 * wxshadow_teardown_page - unified page cleanup.
 *
 * Performs a complete, safe teardown of a shadow page:
 *   1. Under global_lock: mark dead, clear stepping_task, zero pfn_shadow,
 *      remove from page_list (if still present).
 *   2. Disable single-step on the stepping task (with pointer validation).
 *   3. Brief spin for any concurrent step-handler that already passed the
 *      dead check (covers the STEPPING race window).
 *   4. Restore PTE to original page (if mm and VMA are still valid).
 *   5. Release the list's reference via wxshadow_page_put().
 *
 * Shadow page memory is NOT freed here — it is freed in
 * wxshadow_page_put() when the last reference drops, preventing
 * use-after-free by concurrent ref holders.
 *
 * Caller MUST hold a ref (from find_page / find_by_addr) and must call
 * wxshadow_page_put() after this function returns.
 *
 * Safe to call even if the page has already been removed from page_list
 * (list_del_init is idempotent on an initialized-but-empty node).
 */
int wxshadow_teardown_page(struct wxshadow_page *page, const char *reason)
{
    void *stepping = NULL;
    int state;
    bool was_in_list;
    bool finalize_teardown = true;
    int ret = 0;

    if (!page)
        return 0;

    wxshadow_page_pte_lock(page);

    spin_lock(&global_lock);
    if (page->dead) {
        spin_unlock(&global_lock);
        wxshadow_page_pte_unlock(page);
        return 0;
    }

    state = page->state;
    page->release_pending = true;
    if (state == WX_STATE_STEPPING &&
        page->stepping_task && page->stepping_task != current) {
        spin_unlock(&global_lock);
        wxshadow_page_pte_unlock(page);
        pr_info("wxshadow: [teardown] %s: addr=%lx state=%d pending until step completes\n",
                reason, page->page_addr, state);
        return wxshadow_wait_for_teardown(page, reason);
    }

    stepping = page->stepping_task;
    was_in_list = !list_empty(&page->list);
    spin_unlock(&global_lock);

    pr_info("wxshadow: [teardown] %s: addr=%lx state=%d\n",
            reason, page->page_addr, state);

    /* --- Step 2: disable single-step with validation --- */
    if (stepping && stepping != current && kfunc_user_disable_single_step) {
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
    if (state == WX_STATE_STEPPING && stepping && stepping != current) {
        int w;
        for (w = 0; w < 50000; w++)
            cpu_relax();
    }

    /* --- Step 4: restore PTE to original --- */
    if (page->mm && page->pfn_original && kfunc_find_vma) {
        void *mm = page->mm;
        u64 probe;
        if (!is_kva((unsigned long)mm) ||
            !safe_read_u64((unsigned long)mm, &probe)) {
            pr_warn("wxshadow: [teardown] invalid mm %px for addr=%lx\n",
                    mm, page->page_addr);
            ret = -14;
        } else {
            void *vma = kfunc_find_vma(mm, page->page_addr);
            if (!vma || vma_start(vma) > page->page_addr) {
                pr_warn("wxshadow: [teardown] no vma for addr=%lx during %s\n",
                        page->page_addr, reason);
                ret = -14;
            } else {
                ret = wxshadow_page_restore_original_for_teardown_locked(
                    page, vma, page->page_addr);
                if (ret != 0) {
                    pr_warn("wxshadow: [teardown] restore mapping failed for addr=%lx: %d\n",
                            page->page_addr, ret);
                }
            }
        }
    } else if (page->pfn_original) {
        pr_warn("wxshadow: [teardown] missing mm metadata for addr=%lx during %s\n",
                page->page_addr, reason);
        ret = -14;
    }

    if (ret < 0) {
        finalize_teardown = wxshadow_can_finalize_failed_teardown(page);
        if (!finalize_teardown) {
            spin_lock(&global_lock);
            if (!page->dead)
                page->release_pending = false;
            spin_unlock(&global_lock);
            wxshadow_page_pte_unlock(page);
            pr_err("wxshadow: [teardown] retaining page for addr=%lx after restore failure (%d)\n",
                   page->page_addr, ret);
            return ret;
        }

        pr_warn("wxshadow: [teardown] finalize without restore for addr=%lx; mapping already detached\n",
                page->page_addr);
        ret = 0;
    } else {
        wxshadow_sync_shadow_exec_zero(page, reason);
    }

    /* --- Step 5: mark dead, drop from list after mapping is restored --- */
    spin_lock(&global_lock);
    if (!page->dead) {
        page->dead = true;
        page->release_pending = false;
        page->logical_release_pending = false;
        page->state = WX_STATE_NONE;
        page->stepping_task = NULL;

        /* Resource pointer shadow_page is NOT freed here.
         * They are freed in wxshadow_page_put when refcount reaches 0,
         * ensuring no use-after-free by concurrent ref holders. */
        page->pfn_shadow = 0;

        if (was_in_list && !list_empty(&page->list))
            list_del_init(&page->list);
    }
    spin_unlock(&global_lock);

    /* Shadow page freed when last ref drops in page_put */
    if (was_in_list)
        wxshadow_page_put(page);

    wxshadow_page_pte_unlock(page);
    return ret;
}

/*
 * wxshadow_teardown_pages_for_mm - iteratively teardown all pages for a given mm.
 * If mm is NULL, teardown all pages (used during module unload).
 * Returns the number of pages cleaned up.
 */
static int wxshadow_teardown_pages_for_mm_impl(void *mm, const char *reason,
                                               bool strict)
{
    struct list_head *pos;
    struct wxshadow_page *page;
    int count = 0;
    int first_err = 0;

    while (1) {
        page = NULL;
        spin_lock(&global_lock);
        list_for_each(pos, &page_list) {
            struct wxshadow_page *p =
                container_of(pos, struct wxshadow_page, list);
            if (!mm || p->mm == mm) {
                p->refcount++;
                page = p;
                break;
            }
        }
        spin_unlock(&global_lock);

        if (!page)
            break;

        {
            int ret = wxshadow_teardown_page(page, reason);
            if (ret < 0 && first_err == 0)
                first_err = ret;
            if (ret < 0) {
                wxshadow_page_put(page);
                break;
            }
        }
        wxshadow_page_put(page);
        count++;
    }

    if (count > 0)
        pr_info("wxshadow: [%s] cleaned up %d pages\n", reason, count);
    if (first_err < 0)
        pr_warn("wxshadow: [%s] cleanup saw restore failures, first=%d\n",
                reason, first_err);

    return strict ? first_err : count;
}

int wxshadow_teardown_pages_for_mm(void *mm, const char *reason)
{
    return wxshadow_teardown_pages_for_mm_impl(mm, reason, false);
}

int wxshadow_release_pages_for_mm(void *mm, const char *reason)
{
    struct wxshadow_page *batch[32];
    struct list_head *pos;
    int nr;
    int i;
    int count = 0;
    int first_err = 0;
    bool stop = false;

    do {
        nr = 0;

        spin_lock(&global_lock);
        list_for_each(pos, &page_list) {
            struct wxshadow_page *p =
                container_of(pos, struct wxshadow_page, list);

            if (p->dead || p->state == WX_STATE_NONE ||
                p->state == WX_STATE_DORMANT || !p->pfn_shadow)
                continue;
            if (mm && p->mm != mm)
                continue;

            p->refcount++;
            batch[nr++] = p;
            if (nr >= (int)(sizeof(batch) / sizeof(batch[0])))
                break;
        }
        spin_unlock(&global_lock);

        if (nr == 0)
            break;

        for (i = 0; i < nr; i++) {
            int ret = wxshadow_release_page_to_clean_shadow(batch[i], reason);

            if (ret < 0 && first_err == 0)
                first_err = ret;
            if (ret < 0) {
                bool still_active;

                spin_lock(&global_lock);
                still_active = !batch[i]->dead &&
                               batch[i]->state != WX_STATE_DORMANT;
                spin_unlock(&global_lock);
                if (still_active)
                    stop = true;
            }

            wxshadow_page_put(batch[i]);
            count++;
        }
    } while (!stop && nr == (int)(sizeof(batch) / sizeof(batch[0])));

    if (count > 0)
        pr_info("wxshadow: [%s] logically released %d pages\n",
                reason, count);
    if (first_err < 0)
        pr_warn("wxshadow: [%s] logical release saw failures, first=%d\n",
                reason, first_err);

    return first_err;
}

int wxshadow_handle_write_fault(void *mm, unsigned long addr)
{
    struct wxshadow_page *page;
    int ret;

    page = wxshadow_find_page(mm, addr);  /* caller ref */
    if (!page)
        return -1;

    if (page->state == WX_STATE_NONE) {
        wxshadow_page_put(page);
        return -1;
    }

    pr_info("wxshadow: write fault at %lx - page content changing\n", addr);

    ret = wxshadow_release_page_logically(page,
                                          "Write Fault (page modified)");
    if (ret == 0) {
        /*
         * The fault will continue through the kernel's normal write path after
         * we return, so any cached original PFN may become stale due to COW or
         * a successful write-protect resolution. Re-snapshot on next reuse.
         */
        spin_lock(&global_lock);
        if (!page->dead && page->state == WX_STATE_DORMANT) {
            page->pfn_original = 0;
            page->pte_original = 0;
        }
        spin_unlock(&global_lock);
    }
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

    /* Hook exit_mmap - required for safe teardown on process exit */
    ret = hook_wrap1(kfunc_exit_mmap, exit_mmap_before, NULL, NULL);
    if (ret != HOOK_NO_ERR) {
        pr_err("wxshadow: failed to hook exit_mmap: %d\n", ret);
        pr_err("wxshadow: refusing to load without exit_mmap cleanup\n");
        if (kfunc_do_page_fault)
            hook_unwrap(kfunc_do_page_fault, do_page_fault_before, NULL);
        unhook_syscalln(__NR_prctl, prctl_before, NULL);
        if (hook_method == WX_HOOK_METHOD_DIRECT) {
            hook_unwrap(kfunc_single_step_handler, single_step_handler_before, NULL);
            hook_unwrap(kfunc_brk_handler, brk_handler_before, NULL);
        } else if (hook_method == WX_HOOK_METHOD_REGISTER) {
            wx_unregister_brk_step_hooks();
        }
        hook_method = WX_HOOK_METHOD_NONE;
        return -1;
    } else {
        pr_info("wxshadow: hooked exit_mmap for proper cleanup\n");
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

    /* Hook fork protection only on precise mm-duplication callbacks. */
    if (kfunc_dup_mmap) {
        ret = hook_wrap2(kfunc_dup_mmap,
                         before_dup_mmap_wx,
                         after_dup_mmap_wx, NULL);
        if (ret != HOOK_NO_ERR) {
            pr_warn("wxshadow: failed to hook dup_mmap: %d\n", ret);
            kfunc_dup_mmap = NULL;
        } else {
            pr_info("wxshadow: hooked dup_mmap at %px for fork protection\n",
                    kfunc_dup_mmap);
        }
    }
    if (!kfunc_dup_mmap && kfunc_uprobe_dup_mmap) {
        ret = hook_wrap2(kfunc_uprobe_dup_mmap,
                         before_uprobe_dup_mmap_wx,
                         after_uprobe_dup_mmap_wx, NULL);
        if (ret != HOOK_NO_ERR) {
            pr_warn("wxshadow: failed to hook uprobe_dup_mmap: %d\n", ret);
            kfunc_uprobe_dup_mmap = NULL;
        } else {
            pr_info("wxshadow: hooked uprobe_dup_mmap at %px for fork protection\n",
                    kfunc_uprobe_dup_mmap);
        }
    }
    if (!kfunc_dup_mmap && !kfunc_uprobe_dup_mmap) {
        pr_warn("wxshadow: fork protection DISABLED (precise dup_mmap hooks unavailable; copy_process fallback intentionally disabled because it is too broad)\n");
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
    int page_count = 0;

    pr_info("wxshadow: unloading...\n");

    /*
     * Phase 1: Unhook prctl to block new user operations.
     * BRK/step/fault/exit_mmap hooks remain active throughout Phase 2
     * to handle any in-flight operations while pages are being cleaned.
     */
    unhook_syscalln(__NR_prctl, prctl_before, NULL);
    pr_info("wxshadow: unhooked prctl (phase 1)\n");
    wait_for_handlers_drain("phase1-prctl");

    /*
     * Phase 2: Iteratively pop and clean every page from page_list.
     * exit_mmap_before is still active to handle concurrent process exits;
     * it will compete with this loop via global_lock — whoever calls
     * list_del_init first owns the page.
     * BRK/step handlers are still active and will find no page once
     * it has been popped here.
     */
    page_count = wxshadow_teardown_pages_for_mm(NULL, "module unload");

    /*
     * Phase 2.5: Unhook fork protection.
     * Must be done before BRK/step unhook — fork handler may reference
     * shadow pages, but page_list is already empty so it will be a no-op.
     */
    if (kfunc_dup_mmap) {
        hook_unwrap(kfunc_dup_mmap, before_dup_mmap_wx, after_dup_mmap_wx);
        pr_info("wxshadow: unhooked dup_mmap (phase 2.5)\n");
        wait_for_handlers_drain("phase2.5-dup_mmap");
    }
    if (kfunc_uprobe_dup_mmap) {
        hook_unwrap(kfunc_uprobe_dup_mmap,
                    before_uprobe_dup_mmap_wx,
                    after_uprobe_dup_mmap_wx);
        pr_info("wxshadow: unhooked uprobe_dup_mmap (phase 2.5)\n");
        wait_for_handlers_drain("phase2.5-uprobe_dup_mmap");
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
