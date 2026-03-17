/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * W^X Shadow Memory KPM Module - Symbol Resolution and Offset Scanning
 *
 * Kernel symbol resolution, mm_struct/vma/task_struct offset detection.
 *
 * Copyright (C) 2024
 */

#include "wxshadow_internal.h"

/* Cached init_process pointer for use by other detection routines */
static void *wx_init_process = NULL;

/* ========== Safe symbol lookup (vmlinux only, no module traversal) ========== */

/*
 * kallsyms_on_each_symbol callback signature changed in kernel 6.2:
 *   Old: fn(void *data, const char *name, struct module *mod, unsigned long addr)
 *   New: fn(void *data, const char *name, unsigned long addr)
 *
 * We detect which signature is in use at init time by probing with a known
 * symbol (_stext) and comparing the result against kallsyms_lookup_name.
 */

struct lookup_data {
    const char *name;
    unsigned long addr;
};

/* 4-param callback (kernel < 6.2): addr is in 4th argument */
static int lookup_cb_4arg(void *data, const char *name,
                          struct module *mod, unsigned long addr)
{
    struct lookup_data *ld = data;
    if (strcmp(name, ld->name) == 0) {
        ld->addr = addr;
        return 1;
    }
    return 0;
}

/* 3-param callback (kernel >= 6.2): addr is in 3rd argument */
static int lookup_cb_3arg(void *data, const char *name, unsigned long addr)
{
    struct lookup_data *ld = data;
    if (strcmp(name, ld->name) == 0) {
        ld->addr = addr;
        return 1;
    }
    return 0;
}

/* 0 = unknown, 3 = 3-param, 4 = 4-param */
static int cb_param_style = 0;

static void detect_callback_style(void)
{
    struct lookup_data ld;
    unsigned long ref_addr;

    if (!kallsyms_on_each_symbol || !kallsyms_lookup_name)
        return;

    /* Get ground truth from kallsyms_lookup_name */
    ref_addr = kallsyms_lookup_name("_stext");
    if (!ref_addr)
        return;

    /* Try 4-param callback first (older kernels) */
    ld.name = "_stext";
    ld.addr = 0;
    kallsyms_on_each_symbol((void *)lookup_cb_4arg, &ld);
    if (ld.addr == ref_addr) {
        cb_param_style = 4;
        pr_info("wxshadow: kallsyms_on_each_symbol uses 4-param callback\n");
        return;
    }

    /* Try 3-param callback (6.2+) */
    ld.addr = 0;
    kallsyms_on_each_symbol((void *)lookup_cb_3arg, &ld);
    if (ld.addr == ref_addr) {
        cb_param_style = 3;
        pr_info("wxshadow: kallsyms_on_each_symbol uses 3-param callback\n");
        return;
    }

    pr_warn("wxshadow: could not detect kallsyms_on_each_symbol callback style\n");
}

/* Internal: look up a single exact name via vmlinux-only path */
static unsigned long __lookup_name(const char *name)
{
    struct lookup_data ld = { .name = name, .addr = 0 };

    if (kallsyms_on_each_symbol && cb_param_style == 4) {
        kallsyms_on_each_symbol((void *)lookup_cb_4arg, &ld);
        if (ld.addr)
            return ld.addr;
    } else if (kallsyms_on_each_symbol && cb_param_style == 3) {
        kallsyms_on_each_symbol((void *)lookup_cb_3arg, &ld);
        if (ld.addr)
            return ld.addr;
    } else if (kallsyms_lookup_name) {
        /* Last resort: kallsyms_lookup_name (may search modules) */
        return kallsyms_lookup_name(name);
    }
    return 0;
}

/*
 * Safe symbol lookup - only searches vmlinux symbols via kallsyms_on_each_symbol.
 * Falls back to kallsyms_lookup_name only if kallsyms_on_each_symbol unavailable.
 * Automatically tries _noprof variant for kernel 6.10+ renamed symbols.
 */
static unsigned long lookup_name_safe(const char *name)
{
    unsigned long addr = __lookup_name(name);
    if (addr)
        return addr;

    /* Try _noprof variant (kernel 6.10+ memory profiling renames) */
    {
        char noprof_name[128];
        int len = strlen(name);
        if (len + 8 < sizeof(noprof_name)) {
            memcpy(noprof_name, name, len);
            memcpy(noprof_name + len, "_noprof", 8);
            addr = __lookup_name(noprof_name);
        }
    }
    return addr;
}

/* ========== Symbol resolution macros ========== */

/* Use lookup_name_safe for all symbol resolution to avoid module traversal hang */
#define RESOLVE_SYMBOL(name) \
    do { \
        kfunc_##name = (typeof(kfunc_##name))lookup_name_safe(#name); \
        if (!kfunc_##name) { \
            pr_err("wxshadow: failed to find symbol: %s\n", #name); \
            return -1; \
        } \
    } while (0)

#define RESOLVE_SYMBOL_OPTIONAL(name) \
    do { \
        kfunc_##name = (typeof(kfunc_##name))lookup_name_safe(#name); \
    } while (0)

/* ========== Symbol resolution ========== */

int resolve_symbols(void)
{
    pr_info("wxshadow: resolving symbols...\n");

    /* Detect kallsyms_on_each_symbol callback style (3 vs 4 params) */
    detect_callback_style();

    /* ===== Memory management (all exported) ===== */
    pr_info("wxshadow: [1/12] mm functions...\n");
    RESOLVE_SYMBOL(find_vma);
    RESOLVE_SYMBOL(get_task_mm);
    RESOLVE_SYMBOL(mmput);
    /* find_task_by_vpid: use wxfunc(find_task_by_vpid) */

    /* exit_mmap - required, for proper cleanup on process exit */
    kfunc_exit_mmap = (void *)lookup_name_safe("exit_mmap");
    if (kfunc_exit_mmap) {
        pr_info("wxshadow: exit_mmap found at %px\n", kfunc_exit_mmap);
    } else {
        pr_err("wxshadow: exit_mmap not found, refusing to load without exit cleanup\n");
        return -ESRCH;
    }

    /* ===== Page allocation ===== */
    pr_info("wxshadow: [2/12] page alloc...\n");
    kfunc___get_free_pages = (typeof(kfunc___get_free_pages))
        lookup_name_safe("__get_free_pages");
    if (!kfunc___get_free_pages) {
        /* 6.10+: __get_free_pages is inlined, real symbol is get_free_pages_noprof */
        kfunc___get_free_pages = (typeof(kfunc___get_free_pages))
            lookup_name_safe("get_free_pages_noprof");
    }
    if (!kfunc___get_free_pages) {
        pr_err("wxshadow: __get_free_pages not found\n");
        return -1;
    }

    pr_info("wxshadow: [3/12] page free...\n");
    kfunc_free_pages = (typeof(kfunc_free_pages))lookup_name_safe("free_pages");
    if (!kfunc_free_pages) {
        pr_err("wxshadow: free_pages not found\n");
        return -1;
    }

    /* ===== Address translation ===== */
    pr_info("wxshadow: [5/12] address translation...\n");
    kvar_memstart_addr = (s64 *)lookup_name_safe("memstart_addr");
    if (!kvar_memstart_addr) {
        pr_err("wxshadow: memstart_addr not found\n");
        return -1;
    }
    pr_info("wxshadow: memstart_addr=%px, value=0x%llx\n",
            kvar_memstart_addr, *kvar_memstart_addr);

    kvar_physvirt_offset = (s64 *)lookup_name_safe("physvirt_offset");
    if (kvar_physvirt_offset) {
        pr_info("wxshadow: physvirt_offset=%px, value=0x%llx (KASLR mode)\n",
                kvar_physvirt_offset, *kvar_physvirt_offset);
    } else {
        pr_info("wxshadow: physvirt_offset not found, using traditional memstart_addr mode\n");
    }

    /* Determine PAGE_OFFSET based on VA bits from TCR_EL1 */
    {
        u64 tcr_el1_tmp;
        u64 t1sz_tmp, va_bits_tmp;
        unsigned long page_offset_mask;

        asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1_tmp));
        t1sz_tmp = (tcr_el1_tmp >> 16) & 0x3f;
        va_bits_tmp = 64 - t1sz_tmp;

        page_offset_base = ~0UL << (va_bits_tmp - 1);

        {
            unsigned long kaddr = (unsigned long)lookup_name_safe("_stext");
            if (kaddr) {
                page_offset_mask = ~0UL << (va_bits_tmp - 1);
                if ((kaddr & page_offset_mask) != page_offset_base) {
                    pr_warn("wxshadow: PAGE_OFFSET mismatch! calculated=0x%lx, from _stext=0x%lx\n",
                            page_offset_base, kaddr & page_offset_mask);
                    page_offset_base = kaddr & page_offset_mask;
                }
                pr_info("wxshadow: PAGE_OFFSET=0x%lx (va_bits=%lld, _stext=0x%lx)\n",
                        page_offset_base, va_bits_tmp, kaddr);
            } else {
                pr_info("wxshadow: PAGE_OFFSET=0x%lx (va_bits=%lld, calculated)\n",
                        page_offset_base, va_bits_tmp);
            }
        }
    }

    /* Detect correct physvirt offset using AT instruction */
    {
        unsigned long test_vaddr = kfunc___get_free_pages(0xcc0, 0);
        if (test_vaddr) {
            unsigned long real_paddr = vaddr_to_paddr_at(test_vaddr);
            if (real_paddr) {
                detected_physvirt_offset = (s64)test_vaddr - (s64)real_paddr;
                physvirt_offset_valid = 1;
                pr_info("wxshadow: AT translation: vaddr=%lx -> paddr=%lx\n",
                        test_vaddr, real_paddr);
                pr_info("wxshadow: detected physvirt_offset = 0x%llx\n",
                        detected_physvirt_offset);

                unsigned long test_vaddr2 = phys_to_virt_safe(real_paddr);
                pr_info("wxshadow: round-trip test: paddr=%lx -> vaddr=%lx (match=%d)\n",
                        real_paddr, test_vaddr2, test_vaddr == test_vaddr2);
            } else {
                pr_err("wxshadow: AT instruction failed for vaddr=%lx\n", test_vaddr);
            }
            kfunc_free_pages(test_vaddr, 0);
        }
    }

    /* ===== Page table operations ===== */
    pr_info("wxshadow: [6/12] page table ops...\n");

    {
        u64 tcr_el1;
        u64 t1sz, tg1, va_bits;
        asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));

        t1sz = (tcr_el1 >> 16) & 0x3f;
        va_bits = 64 - t1sz;

        tg1 = (tcr_el1 >> 30) & 0x3;
        wx_page_shift = 12;
        if (tg1 == 1) {
            wx_page_shift = 14;
        } else if (tg1 == 3) {
            wx_page_shift = 16;
        }

        wx_page_level = (va_bits - 4) / (wx_page_shift - 3);

        pr_info("wxshadow: TCR_EL1=0x%llx, va_bits=%lld, page_shift=%d, page_level=%d\n",
                tcr_el1, va_bits, wx_page_shift, wx_page_level);
    }

    /* Spinlock and task functions - using lookup_name_safe */
    wx__raw_spin_lock = (typeof(wx__raw_spin_lock))lookup_name_safe("_raw_spin_lock");
    wx__raw_spin_unlock = (typeof(wx__raw_spin_unlock))lookup_name_safe("_raw_spin_unlock");
    wx_find_task_by_vpid = (typeof(wx_find_task_by_vpid))lookup_name_safe("find_task_by_vpid");
    wx___task_pid_nr_ns = (typeof(wx___task_pid_nr_ns))lookup_name_safe("__task_pid_nr_ns");
    if (!wxfunc(_raw_spin_lock) || !wxfunc(_raw_spin_unlock) ||
        !wxfunc(find_task_by_vpid) || !wxfunc(__task_pid_nr_ns)) {
        pr_err("wxshadow: required kernel functions not found\n");
        return -1;
    }

    /* init_task - looked up via lookup_name_safe since framework doesn't export it */
    wx_init_task = (struct task_struct *)lookup_name_safe("init_task");
    if (!wx_init_task) {
        pr_err("wxshadow: init_task not found\n");
        return -1;
    }
    pr_info("wxshadow: wx_init_task at %px\n", wx_init_task);

    /* TLB flush - try flush_tlb_page first, fallback to __flush_tlb_range, then TLBI */
    kfunc_flush_tlb_page = (typeof(kfunc_flush_tlb_page))
        lookup_name_safe("flush_tlb_page");
    if (kfunc_flush_tlb_page) {
        pr_info("wxshadow: flush_tlb_page at %px\n", kfunc_flush_tlb_page);
    } else {
        /* flush_tlb_page is inline on some kernels, try __flush_tlb_range */
        kfunc___flush_tlb_range = (typeof(kfunc___flush_tlb_range))
            lookup_name_safe("__flush_tlb_range");
        if (kfunc___flush_tlb_range) {
            pr_info("wxshadow: using __flush_tlb_range at %px (fallback)\n", kfunc___flush_tlb_range);
        } else {
            /* Neither found - will use TLBI instruction fallback */
            pr_warn("wxshadow: neither flush_tlb_page nor __flush_tlb_range found\n");
            pr_info("wxshadow: will use TLBI instruction fallback (requires mm->context.id detection)\n");
        }
    }

    /* ===== THP split (optional) ===== */
    kfunc___split_huge_pmd = (typeof(kfunc___split_huge_pmd))
        lookup_name_safe("__split_huge_pmd");
    if (kfunc___split_huge_pmd) {
        pr_info("wxshadow: __split_huge_pmd at %px\n", kfunc___split_huge_pmd);
    } else {
        pr_info("wxshadow: __split_huge_pmd not found (THP disabled or inlined)\n");
    }

    /* ===== Cache operations ===== */
    pr_info("wxshadow: [7/12] cache ops...\n");
    RESOLVE_SYMBOL(flush_dcache_page);

    kfunc___flush_icache_range = (typeof(kfunc___flush_icache_range))
        lookup_name_safe("__flush_icache_range");
    if (!kfunc___flush_icache_range) {
        kfunc___flush_icache_range = (typeof(kfunc___flush_icache_range))
            lookup_name_safe("flush_icache_range");
    }
    if (!kfunc___flush_icache_range) {
        kfunc___flush_icache_range = (typeof(kfunc___flush_icache_range))
            lookup_name_safe("__flush_cache_user_range");
    }
    if (!kfunc___flush_icache_range) {
        kfunc___flush_icache_range = (typeof(kfunc___flush_icache_range))
            lookup_name_safe("invalidate_icache_range");
    }
    /* 6.1+ ARM64 renamed cache maintenance functions */
    if (!kfunc___flush_icache_range) {
        kfunc___flush_icache_range = (typeof(kfunc___flush_icache_range))
            lookup_name_safe("caches_clean_inval_pou");
    }
    if (!kfunc___flush_icache_range) {
        kfunc___flush_icache_range = (typeof(kfunc___flush_icache_range))
            lookup_name_safe("caches_clean_inval_user_pou");
    }
    if (kfunc___flush_icache_range) {
        pr_info("wxshadow: using kernel icache flush at %px\n", kfunc___flush_icache_range);
    } else {
        pr_info("wxshadow: using built-in icache flush (dc cvau + ic ialluis)\n");
    }

    /* ===== Debug functions ===== */
    pr_info("wxshadow: [8/12] debug/single-step...\n");
    kfunc_user_enable_single_step = (typeof(kfunc_user_enable_single_step))
        lookup_name_safe("user_enable_single_step");
    kfunc_user_disable_single_step = (typeof(kfunc_user_disable_single_step))
        lookup_name_safe("user_disable_single_step");
    if (!kfunc_user_enable_single_step || !kfunc_user_disable_single_step) {
        pr_err("wxshadow: single step functions not found\n");
        return -1;
    }

    /* ===== BRK/Step hooks ===== */
    pr_info("wxshadow: [9/12] BRK/step hooks...\n");

    /* Resolve all symbols - let wxshadow_init decide priority */
    /* Direct hook symbols */
    kfunc_brk_handler = (void *)lookup_name_safe("brk_handler");
    kfunc_single_step_handler = (void *)lookup_name_safe("single_step_handler");
    pr_info("wxshadow: brk_handler = %px\n", kfunc_brk_handler);
    pr_info("wxshadow: single_step_handler = %px\n", kfunc_single_step_handler);

    /* Register API symbols */
    kfunc_register_user_break_hook = (typeof(kfunc_register_user_break_hook))
        lookup_name_safe("register_user_break_hook");
    kfunc_register_user_step_hook = (typeof(kfunc_register_user_step_hook))
        lookup_name_safe("register_user_step_hook");

    pr_info("wxshadow: register_user_break_hook = %px\n", kfunc_register_user_break_hook);
    pr_info("wxshadow: register_user_step_hook = %px\n", kfunc_register_user_step_hook);

    /* debug_hook_lock for safe manual unregister */
    kptr_debug_hook_lock = (spinlock_t *)lookup_name_safe("debug_hook_lock");
    pr_info("wxshadow: debug_hook_lock = %px\n", kptr_debug_hook_lock);

    /* Check if at least one method is available */
    if (!(kfunc_brk_handler && kfunc_single_step_handler) &&
        !(kfunc_register_user_break_hook && kfunc_register_user_step_hook)) {
        pr_err("wxshadow: neither direct hook nor register API available\n");
        return -1;
    }
    pr_info("wxshadow: [9/12] done\n");

    /* ===== Locking ===== */
    /* NOTE: mmap_lock and page_table_lock are NOT used - we operate locklessly */
    pr_info("wxshadow: [10/12] locking... (skipped - lockless operation)\n");

    /* ===== RCU ===== */
    pr_info("wxshadow: [11/12] RCU...\n");
    kfunc_rcu_read_lock = (typeof(kfunc_rcu_read_lock))
        lookup_name_safe("__rcu_read_lock");
    kfunc_rcu_read_unlock = (typeof(kfunc_rcu_read_unlock))
        lookup_name_safe("__rcu_read_unlock");
    kfunc_synchronize_rcu = (typeof(kfunc_synchronize_rcu))
        lookup_name_safe("synchronize_rcu");
    kfunc_kick_all_cpus_sync = (typeof(kfunc_kick_all_cpus_sync))
        lookup_name_safe("kick_all_cpus_sync");
    if (!kfunc_rcu_read_lock || !kfunc_rcu_read_unlock) {
        pr_err("wxshadow: RCU functions not found\n");
        return -1;
    }
    if (!kfunc_kick_all_cpus_sync) {
        pr_err("wxshadow: kick_all_cpus_sync not found, refusing to load\n");
        return -ESRCH;
    }
    pr_info("wxshadow: synchronize_rcu = %px\n", kfunc_synchronize_rcu);
    pr_info("wxshadow: kick_all_cpus_sync = %px\n", kfunc_kick_all_cpus_sync);

    /* ===== Memory allocation ===== */
    pr_info("wxshadow: [12/12] memory alloc...\n");
    kfunc_kzalloc = (typeof(kfunc_kzalloc))lookup_name_safe("kzalloc");
    if (!kfunc_kzalloc)
        kfunc_kzalloc = (typeof(kfunc_kzalloc))lookup_name_safe("__kmalloc");
    if (!kfunc_kzalloc)
        kfunc_kzalloc = (typeof(kfunc_kzalloc))lookup_name_safe("__kmalloc_node");
    if (!kfunc_kzalloc)
        kfunc_kzalloc = (typeof(kfunc_kzalloc))lookup_name_safe("kmalloc_trace");
    if (!kfunc_kzalloc) {
        pr_err("wxshadow: kzalloc/__kmalloc not found\n");
        return -1;
    }
    pr_info("wxshadow: kzalloc resolved to %px\n", kfunc_kzalloc);

    /* Use lookup_name_safe to avoid module traversal hang */
    kfunc_kcalloc = (typeof(kfunc_kcalloc))lookup_name_safe("kcalloc");
    if (!kfunc_kcalloc)
        kfunc_kcalloc = (typeof(kfunc_kcalloc))lookup_name_safe("kmalloc_array");
    if (!kfunc_kcalloc) {
        pr_warn("wxshadow: kcalloc/kmalloc_array not found, will use kzalloc wrapper\n");
    } else {
        pr_info("wxshadow: kcalloc resolved to %px\n", kfunc_kcalloc);
    }

    kfunc_kfree = (typeof(kfunc_kfree))lookup_name_safe("kfree");
    if (!kfunc_kfree) {
        pr_err("wxshadow: kfree not found\n");
        return -1;
    }
    pr_info("wxshadow: kfree resolved to %px\n", kfunc_kfree);

    /* Safe memory access - try copy_from_kernel_nofault first, fallback to probe_kernel_read */
    kfunc_copy_from_kernel_nofault = (typeof(kfunc_copy_from_kernel_nofault))
        lookup_name_safe("copy_from_kernel_nofault");
    if (!kfunc_copy_from_kernel_nofault) {
        kfunc_copy_from_kernel_nofault = (typeof(kfunc_copy_from_kernel_nofault))
            lookup_name_safe("probe_kernel_read");
    }
    if (kfunc_copy_from_kernel_nofault) {
        pr_info("wxshadow: safe memory access available at %px\n", kfunc_copy_from_kernel_nofault);
    } else {
        pr_warn("wxshadow: copy_from_kernel_nofault not found, using direct access (less safe)\n");
    }

    /* copy_from_user removed: PATCH uses PTE walk instead (see copy_from_user_via_pte) */

    /* ===== Page fault handler (optional) ===== */
    /*
     * Use lookup_name_safe() to avoid module traversal hang.
     * kallsyms_lookup_name() calls module_kallsyms_lookup_name() when
     * symbol is not found in vmlinux, which can hang on some kernels.
     */
    pr_info("wxshadow: [13/14] page fault handler (safe lookup)...\n");
    kfunc_do_page_fault = (void *)lookup_name_safe("do_page_fault");
    if (!kfunc_do_page_fault) {
        /* Try alternative names used in different kernel versions */
        kfunc_do_page_fault = (void *)lookup_name_safe("__do_page_fault");
    }
    if (!kfunc_do_page_fault) {
        kfunc_do_page_fault = (void *)lookup_name_safe("do_mem_abort");
    }
    if (!kfunc_do_page_fault) {
        pr_warn("wxshadow: page fault handler not found, read hiding disabled\n");
    } else {
        pr_info("wxshadow: page fault handler found at %px\n", kfunc_do_page_fault);
    }

    /* follow_page_pte for GUP hiding (/proc/pid/mem, process_vm_readv, ptrace) */
    pr_info("wxshadow: [14/14] follow_page_pte (GUP hiding)...\n");
    kfunc_follow_page_pte = (void *)lookup_name_safe("follow_page_pte");
    if (kfunc_follow_page_pte) {
        pr_info("wxshadow: follow_page_pte found at %px\n", kfunc_follow_page_pte);
    } else {
        pr_warn("wxshadow: follow_page_pte not found, GUP hiding disabled\n");
    }

    /* dup_mmap for precise fork protection (real mm duplication only) */
    kfunc_dup_mmap = (void *)lookup_name_safe("dup_mmap");
    if (kfunc_dup_mmap) {
        pr_info("wxshadow: dup_mmap found at %px\n", kfunc_dup_mmap);
    } else {
        pr_warn("wxshadow: dup_mmap not found, trying uprobe_dup_mmap\n");
    }

    kfunc_uprobe_dup_mmap = (void *)lookup_name_safe("uprobe_dup_mmap");
    if (kfunc_uprobe_dup_mmap) {
        pr_info("wxshadow: uprobe_dup_mmap found at %px\n", kfunc_uprobe_dup_mmap);
    } else {
        pr_warn("wxshadow: uprobe_dup_mmap not found\n");
    }

    /* init_task already resolved above via kallsyms */

    pr_info("wxshadow: all symbols resolved successfully\n");
    return 0;
}

/* ========== mm_struct offset scanning ========== */

/* Check if a kernel address is valid and readable */
static inline bool is_valid_kptr(unsigned long addr)
{
    u64 tmp;
    return safe_read_u64(addr, &tmp);
}

/* Safely read a string (up to maxlen bytes) */
static inline bool safe_read_str(unsigned long addr, char *buf, size_t maxlen)
{
    if (!is_kva(addr) || maxlen == 0)
        return false;

    if (kfunc_copy_from_kernel_nofault) {
        if (kfunc_copy_from_kernel_nofault(buf, (const void *)addr, maxlen) != 0)
            return false;
    } else {
        /* Fallback: byte-by-byte copy */
        size_t i;
        for (i = 0; i < maxlen; i++) {
            buf[i] = ((char *)addr)[i];
        }
    }
    buf[maxlen - 1] = '\0';
    return true;
}

int scan_mm_struct_offsets(void)
{
    /*
     * Use KP framework's mm_struct_offset.pgd_offset (linux/mm_types.h)
     * Framework detects this in resolve_mm_struct_offset() at boot time.
     */
    pr_info("wxshadow: using KP framework mm_struct_offset.pgd_offset = 0x%x\n",
            mm_struct_offset.pgd_offset);

    if (mm_struct_offset.pgd_offset < 0) {
        pr_err("wxshadow: KP framework did not detect pgd_offset!\n");
        return -1;
    }

    return 0;
}

/* ========== VMA offset scanning ========== */

int scan_vma_struct_offsets(void)
{
    void *mm;
    void *vma;
    int i;
    int found = 0;

    pr_info("wxshadow: scanning vm_area_struct offsets...\n");

    /*
     * Use current task's mm to find vma offset.
     * If current has no mm (kernel thread), use default.
     */
    mm = kfunc_get_task_mm(current);
    if (!mm) {
        pr_warn("wxshadow: current task has no mm, using default vma offset\n");
        goto scan_known;
    }

    /*
     * Get first VMA from mm_struct.
     *
     * Kernel <6.1: mm->mmap is the first field of mm_struct (a direct VMA pointer).
     * Kernel 6.1+: mm->mmap removed, VMA stored in mm->mm_mt (maple tree).
     *              Use find_vma(mm, 0) to retrieve it.
     *
     * Try find_vma first (works on all versions), fall back to reading mm->mmap.
     */
    vma = kfunc_find_vma(mm, 0);
    if (!vma) {
        /* Fallback: try reading mm->mmap (first pointer in mm_struct, old kernels) */
        safe_read_ptr((unsigned long)mm, &vma);
    }
    if (!vma || !is_kva((unsigned long)vma)) {
        pr_warn("wxshadow: no VMA in current mm, scanning with known offsets\n");
        kfunc_mmput(mm);
        goto scan_known;
    }

    /* Sanity check: vma->vm_start should be a user-space address (< PAGE_OFFSET) */
    {
        u64 check_start;
        if (!safe_read_u64((unsigned long)vma, &check_start) ||
            is_kva(check_start) || check_start == 0) {
            pr_warn("wxshadow: VMA at %px looks invalid (vm_start=%llx)\n",
                    vma, check_start);
            kfunc_mmput(mm);
            goto scan_known;
        }
    }

    pr_info("wxshadow: scanning VMA at %px for mm pointer %px\n", vma, mm);

    /*
     * Dynamically detect vm_mm offset by scanning vm_area_struct fields.
     * vm_start(0x00) and vm_end(0x08) are always at the beginning,
     * so vm_mm must be at offset >= 0x10.  Search up to 0x100 to cover
     * future kernel versions that may add fields before vm_mm.
     */
    for (i = 0x10; i < 0x100; i += 8) {
        u64 val;
        if (!safe_read_u64((unsigned long)vma + i, &val))
            continue;
        if (val == (u64)mm) {
            vma_vm_mm_offset = i;
            found = 1;
            pr_info("wxshadow: vm_area_struct.vm_mm offset: 0x%x (detected)\n",
                    vma_vm_mm_offset);
            break;
        }
    }

    kfunc_mmput(mm);

    if (found)
        return 0;

    pr_warn("wxshadow: vm_mm offset not found by dynamic scan\n");

scan_known:
    /*
     * Fallback: try known offsets from various kernel versions.
     * 0x10: kernel 6.1+ (vm_mm right after vm_start/vm_end)
     * 0x40: kernel 4.x-6.0 (vm_mm after rb_node/rb_subtree fields)
     *
     * Cannot validate without a valid VMA pointer, so log a warning
     * and pick the most likely based on kernel version.
     */
    {
        /* KP provides kernel version; prefer version-aware selection */
        static const int known_offsets[] = { 0x10, 0x40 };
        int n = sizeof(known_offsets) / sizeof(known_offsets[0]);
        for (i = 0; i < n; i++) {
            vma_vm_mm_offset = known_offsets[i];
            pr_warn("wxshadow: using fallback vm_mm offset: 0x%x "
                    "(UNVERIFIED — dynamic scan failed)\n",
                    vma_vm_mm_offset);
            return 0;
        }
    }
    pr_err("wxshadow: failed to determine vm_mm offset\n");
    return -1;
}

/* ========== task_struct offset detection ========== */

#define TASK_COMM_LEN 16
#define TASK_STRUCT_MAX_SIZE 0x1800

/* Find comm offset by searching for "swapper" or "swapper/0" in task_struct */
static int find_comm_offset(void *task)
{
    int i;
    char buf[16];

    for (i = 0x400; i < TASK_STRUCT_MAX_SIZE; i += 4) {
        /* Safely read potential comm string */
        if (!safe_read_str((unsigned long)task + i, buf, sizeof(buf)))
            continue;

        /* Check for "swapper" or "swapper/0" */
        if (buf[0] == 's' && buf[1] == 'w' && buf[2] == 'a' &&
            buf[3] == 'p' && buf[4] == 'p' && buf[5] == 'e' && buf[6] == 'r') {
            /* Verify it's null-terminated or followed by "/" */
            if (buf[7] == '\0' || (buf[7] == '/' && buf[8] == '0')) {
                pr_info("wxshadow: found comm at offset 0x%x: \"%.16s\"\n", i, buf);
                return i;
            }
        }
    }

    return -1;
}

int detect_task_struct_offsets(void)
{
    int search_start, search_end;
    int i;
    int16_t comm_offset;
    int16_t active_mm_off;

    pr_info("wxshadow: detecting task_struct offsets...\n");

    if (!wx_init_task) {
        pr_err("wxshadow: wx_init_task is NULL\n");
        return -1;
    }

    /* First, scan for comm_offset if not already set by framework */
    comm_offset = task_struct_offset.comm_offset;
    if (comm_offset <= 0) {
        comm_offset = find_comm_offset(wx_init_task);
        if (comm_offset > 0) {
            task_struct_offset.comm_offset = comm_offset;
            pr_info("wxshadow: comm_offset = 0x%x (scanned)\n", comm_offset);
        } else {
            pr_err("wxshadow: failed to find comm_offset\n");
            return -1;
        }
    } else {
        pr_info("wxshadow: comm_offset = 0x%x (from framework)\n", comm_offset);
    }

    /* Get active_mm_offset from framework */
    active_mm_off = task_struct_offset.active_mm_offset;

    /*
     * Detect tasks_offset based on active_mm_offset
     *
     * In Linux kernel task_struct layout, tasks (struct list_head) is
     * typically located before mm and active_mm fields:
     *   struct task_struct {
     *       ...
     *       struct list_head tasks;    <- tasks_offset
     *       ...
     *       struct mm_struct *mm;      <- mm_offset (active_mm - 8)
     *       struct mm_struct *active_mm; <- active_mm_offset
     *       ...
     *   }
     *
     * Search range: [active_mm_offset - 0x200, active_mm_offset)
     */
    if (active_mm_off > 0) {
        search_start = active_mm_off > 0x200 ? active_mm_off - 0x200 : 0x100;
        search_end = active_mm_off;
        pr_info("wxshadow: scanning tasks_offset based on active_mm_offset=0x%x, range=[0x%x, 0x%x)\n",
                active_mm_off, search_start, search_end);
    } else {
        /* Fallback: use comm_offset as upper bound */
        search_start = 0x100;
        search_end = comm_offset < 0x600 ? comm_offset : 0x600;
        pr_info("wxshadow: active_mm_offset not available, fallback range=[0x%x, 0x%x)\n",
                search_start, search_end);
    }

    /* Detect tasks_offset (not provided by framework) */
    for (i = search_start; i < search_end; i += sizeof(u64)) {
        unsigned long list_addr = (unsigned long)wx_init_task + i;
        u64 next_va, prev_va;

        /* Safely read list_head.next and list_head.prev */
        if (!safe_read_u64(list_addr, &next_va))
            continue;
        if (!safe_read_u64(list_addr + 8, &prev_va))
            continue;

        if (!is_kva(next_va) || !is_kva(prev_va))
            continue;

        if (next_va == prev_va)
            continue;

        /* Verify next->prev == self */
        {
            u64 next_prev;
            if (!safe_read_u64(next_va + 8, &next_prev))
                continue;
            if (next_prev != list_addr)
                continue;
        }

        /* Verify the candidate task has comm == "init" */
        {
            void *candidate = (void *)(next_va - i);
            char comm_buf[8];

            if (!safe_read_str((unsigned long)candidate + comm_offset, comm_buf, sizeof(comm_buf)))
                continue;

            if (comm_buf[0] == 'i' && comm_buf[1] == 'n' &&
                comm_buf[2] == 'i' && comm_buf[3] == 't') {
                task_struct_offset.tasks_offset = i;
                wx_init_process = candidate;
                pr_info("wxshadow: tasks_offset = 0x%x (based on active_mm_offset=0x%x)\n",
                        i, active_mm_off);
                break;
            }
        }
    }

    if (task_struct_offset.tasks_offset < 0) {
        pr_err("wxshadow: tasks_offset not found\n");
        return -1;
    }

    /*
     * Detect mm_offset using active_mm_offset from framework
     *
     * mm is always 8 bytes before active_mm in task_struct:
     *   struct mm_struct *mm;        <- mm_offset
     *   struct mm_struct *active_mm; <- active_mm_offset
     */
    if (task_struct_offset.active_mm_offset > 0) {
        task_struct_offset.mm_offset = task_struct_offset.active_mm_offset - 8;
        pr_info("wxshadow: mm_offset = 0x%x (active_mm_offset - 8)\n",
                task_struct_offset.mm_offset);
    } else {
        pr_err("wxshadow: active_mm_offset not available from framework\n");
        return -1;
    }

    /* pid/tgid: use wxfunc(__task_pid_nr_ns) */

    pr_info("wxshadow: task_struct offsets: tasks=0x%x, mm=0x%x, comm=0x%x\n",
            task_struct_offset.tasks_offset, task_struct_offset.mm_offset,
            task_struct_offset.comm_offset);
    pr_info("wxshadow: pid/tgid: using wxfunc(__task_pid_nr_ns)\n");

    return 0;
}

/* ========== mm->context.id offset scanning ========== */

/* ELF magic bytes */
#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

/*
 * Translate user VA to PA by walking mm's page table.
 * Uses TCR_EL1.T0SZ and TG0 for user space address translation.
 * Returns: PA on success, 0 on failure
 */
static unsigned long walk_pgtable_uaddr(void *mm, unsigned long uaddr)
{
    u64 *table;
    u64 desc;
    int level;
    u64 tcr;
    int t0sz, tg0;
    int granule_shift, stride;
    int va_bits, levels, start_level;

    /* Get PGD from mm - it's already a kernel virtual address */
    table = (u64 *)mm_pgd(mm);
    if (!table || !is_kva((unsigned long)table))
        return 0;

    /* Read TCR_EL1 to get T0SZ and TG0 */
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr));

    t0sz = tcr & 0x3f;
    tg0 = (tcr >> 14) & 0x3;

    /* Decode TG0: 0=4KB, 1=64KB, 2=16KB */
    switch (tg0) {
    case 0:  /* 4KB */
        granule_shift = 12;
        stride = 9;
        break;
    case 1:  /* 64KB */
        granule_shift = 16;
        stride = 13;
        break;
    case 2:  /* 16KB */
        granule_shift = 14;
        stride = 11;
        break;
    default:
        granule_shift = 12;
        stride = 9;
    }

    va_bits = 64 - t0sz;
    levels = (va_bits - granule_shift + stride - 1) / stride;
    start_level = 4 - levels;

    for (level = start_level; level <= 3; level++) {
        int shift = granule_shift + stride * (3 - level);
        int idx = (uaddr >> shift) & ((1 << stride) - 1);

        /* Read descriptor directly (table is KVA) */
        if (!safe_read_u64((unsigned long)&table[idx], &desc))
            return 0;

        /* Check valid bit */
        if (!(desc & 1))
            return 0;

        unsigned long next_pa = desc & 0x0000FFFFFFFFF000UL;

        /* Check if table or block/page entry */
        if (level < 3 && (desc & 2)) {
            /* Table descriptor - convert PA to KVA for next level */
            table = (u64 *)phys_to_virt_safe(next_pa);
            if (!is_kva((unsigned long)table))
                return 0;
        } else {
            /* Block or page entry - translation complete */
            unsigned long offset_mask = (1UL << shift) - 1;
            return next_pa | (uaddr & offset_mask);
        }
    }

    return 0;
}

/*
 * Check if address contains ELF magic by walking mm's page table.
 * Returns: true if ELF magic found, false otherwise
 */
static bool check_elf_magic_at_uaddr(void *mm, unsigned long uaddr, int mm_offset)
{
    unsigned long pa, kva;
    unsigned char magic[4] = {0, 0, 0, 0};
    bool found;

    /* Must be a user address (not kernel) */
    if ((uaddr >> 48) != 0)
        return false;

    if (uaddr == 0)
        return false;

    /* Walk mm's page table to translate user VA to PA */
    pa = walk_pgtable_uaddr(mm, uaddr);
    if (pa == 0) {
        pr_info("wxshadow:   [0x%x] uaddr=0x%lx -> PA failed\n", mm_offset, uaddr);
        return false;
    }

    /* Convert PA to kernel VA */
    kva = phys_to_virt_safe(pa);
    if (!is_kva(kva)) {
        pr_info("wxshadow:   [0x%x] uaddr=0x%lx -> pa=0x%lx -> kva invalid\n",
                mm_offset, uaddr, pa);
        return false;
    }

    /* Read the first 4 bytes */
    if (kfunc_copy_from_kernel_nofault) {
        if (kfunc_copy_from_kernel_nofault(magic, (const void *)kva, 4) != 0) {
            pr_info("wxshadow:   [0x%x] uaddr=0x%lx -> kva=0x%lx read failed\n",
                    mm_offset, uaddr, kva);
            return false;
        }
    } else {
        magic[0] = ((unsigned char *)kva)[0];
        magic[1] = ((unsigned char *)kva)[1];
        magic[2] = ((unsigned char *)kva)[2];
        magic[3] = ((unsigned char *)kva)[3];
    }

    /* Check ELF magic */
    found = (magic[0] == ELFMAG0 && magic[1] == ELFMAG1 &&
             magic[2] == ELFMAG2 && magic[3] == ELFMAG3);

    pr_info("wxshadow:   [0x%x] uaddr=0x%lx -> magic=%02x %02x %02x %02x %s\n",
            mm_offset, uaddr, magic[0], magic[1], magic[2], magic[3],
            found ? "** ELF FOUND **" : "");

    return found;
}

/*
 * Scan mm->context.id by finding vdso (ELF magic pointer).
 * context.id is right before vdso in mm_context_t.
 *
 * mm_context_t layout:
 *   atomic64_t id;      <- context.id (what we want)
 *   void *vdso;         <- points to ELF magic
 *   ...
 *
 * Returns: context.id offset on success, -1 on failure
 */
static int scan_by_vdso_elf_magic(struct mm_struct *mm)
{
    int offset;
    int pgd_off = mm_struct_offset.pgd_offset;
    u64 val;
    int user_ptr_count = 0;

    if (pgd_off < 0) {
        pr_warn("wxshadow: pgd_offset not available\n");
        return -1;
    }

    pr_info("wxshadow: scanning for vdso (ELF magic) in mm=%px, pgd_offset=0x%x\n",
            mm, pgd_off);
    pr_info("wxshadow: search range: [0x%x, 0x%x)\n",
            pgd_off + 0x100, pgd_off + 0x400);

    /* Search for vdso pointer after pgd */
    for (offset = pgd_off + 0x100; offset < pgd_off + 0x400; offset += 8) {
        if (!safe_read_u64((unsigned long)mm + offset, &val))
            continue;

        /* Skip NULL and kernel addresses */
        if (val == 0 || (val >> 48) != 0)
            continue;

        /* Found a user-space pointer, check if it points to ELF magic */
        user_ptr_count++;
        if (check_elf_magic_at_uaddr(mm, val, offset)) {
            pr_info("wxshadow: === VDSO FOUND at mm+0x%x, vdso_addr=0x%llx ===\n",
                    offset, val);

            /* context.id is right before vdso (8 bytes) */
            return offset - 8;
        }
    }

    pr_warn("wxshadow: vdso not found (checked %d user pointers)\n", user_ptr_count);
    return -1;
}

/*
 * Scan mm->context.id offset using TTBR0_EL1 ASID (primary method).
 * Returns: offset on success, -1 on failure, -2 if ASID=0
 */
static int scan_by_ttbr0_asid(struct mm_struct *mm)
{
    u64 ttbr0_val, asid;
    int offset;

    /* Read TTBR0_EL1 to get ASID */
    asm volatile("mrs %0, ttbr0_el1" : "=r"(ttbr0_val));

    /* ASID is in bits [63:48] (16-bit ASID) or [55:48] (8-bit ASID) */
    asid = (ttbr0_val >> 48) & 0xFFFF;

    pr_info("wxshadow: TTBR0_EL1=0x%llx, ASID=%llu (0x%llx)\n", ttbr0_val, asid, asid);

    /* ASID=0 is problematic - too many zero fields would match */
    if (asid == 0) {
        pr_info("wxshadow: ASID=0, cannot use TTBR0 method\n");
        return -2;
    }

    /* Search for context.id in mm_struct */
    for (offset = 0x100; offset < 0x400; offset += 8) {
        u64 val;
        if (!safe_read_u64((unsigned long)mm + offset, &val))
            continue;

        /* Check if low 16 bits match ASID */
        if ((val & 0xFFFF) == asid) {
            pr_info("wxshadow: found mm->context.id at offset 0x%x, val=0x%llx (ASID match)\n",
                    offset, val);
            return offset;
        }
    }

    /* Try alternative: ASID might be in higher bits */
    for (offset = 0x100; offset < 0x400; offset += 8) {
        u64 val;
        if (!safe_read_u64((unsigned long)mm + offset, &val))
            continue;

        if (((val >> 48) & 0xFFFF) == asid ||
            ((val >> 32) & 0xFFFF) == asid) {
            pr_info("wxshadow: found mm->context.id at offset 0x%x (alt), val=0x%llx\n",
                    offset, val);
            return offset;
        }
    }

    pr_warn("wxshadow: TTBR0 method failed (ASID=%llu)\n", asid);
    return -1;
}

/*
 * Scan mm->context.id offset using TTBR0_EL1 ASID.
 * Must be called from user process context (not kernel thread).
 *
 * Returns: offset on success, -1 on failure
 */
static int scan_mm_context_id_offset_from_mm(struct mm_struct *mm)
{
    int offset;

    /* Validate mm pointer is readable */
    if (!is_valid_kptr((unsigned long)mm)) {
        pr_warn("wxshadow: invalid mm pointer: %px\n", mm);
        return -1;
    }

    /* Use TTBR0 ASID matching - only reliable method */
    pr_info("wxshadow: scanning mm->context.id using TTBR0 ASID method...\n");
    offset = scan_by_ttbr0_asid(mm);
    if (offset >= 0) {
        pr_info("wxshadow: mm_context_id_offset = 0x%x\n", offset);
        return offset;
    }

    pr_warn("wxshadow: TTBR0 ASID method failed (ASID may be 0 in kernel thread context)\n");
    return -1;
}

/*
 * Get init process (pid 1) mm_struct.
 * Uses wx_init_process cached from task_struct detection.
 */
static struct mm_struct *get_init_process_mm(void)
{
    struct task_struct *init_proc;
    struct mm_struct *mm = NULL;

    /* Use cached init_process from detect_task_struct_offsets */
    init_proc = wx_init_process;
    if (!init_proc) {
        pr_warn("wxshadow: init process not found\n");
        return NULL;
    }

    /* Get mm from init process */
    if (task_struct_offset.mm_offset >= 0) {
        safe_read_ptr((unsigned long)init_proc + task_struct_offset.mm_offset, (void **)&mm);
    }

    if (!mm) {
        pr_warn("wxshadow: init process has no mm\n");
        return NULL;
    }

    pr_info("wxshadow: init process mm=%px\n", mm);
    return mm;
}

/*
 * Try to scan mm->context.id offset.
 * Primary method: Find vdso (ELF magic) in init process mm, context.id is before it.
 * Fallback: TTBR0 ASID matching (requires user process context).
 *
 * Returns: 0 on success, -1 on failure (will retry later)
 */
int try_scan_mm_context_id_offset(void)
{
    struct mm_struct *mm;
    int offset;

    /* Already detected */
    if (mm_context_id_offset >= 0)
        return 0;

    pr_info("wxshadow: trying to scan mm->context.id offset...\n");

    /*
     * Method 1: Use init process (pid 1) mm and find vdso by ELF magic.
     * This works regardless of current context (kernel thread or user process).
     */
    mm = get_init_process_mm();
    if (mm) {
        offset = scan_by_vdso_elf_magic(mm);
        if (offset >= 0) {
            pr_info("wxshadow: mm_context_id_offset = 0x%x (vdso method)\n", offset);
            mm_context_id_offset = offset;
            return 0;
        }
    }

    /*
     * Method 2 (fallback): Use current process mm and TTBR0 ASID matching.
     * Only works in user process context.
     */
    if (task_struct_offset.mm_offset < 0) {
        pr_warn("wxshadow: mm_offset not detected\n");
        return -1;
    }

    if (!safe_read_ptr((unsigned long)current + task_struct_offset.mm_offset, (void **)&mm)) {
        pr_warn("wxshadow: failed to read mm from current task\n");
        return -1;
    }

    if (!mm) {
        pr_info("wxshadow: current is kernel thread, deferring to prctl\n");
        return -1;
    }

    offset = scan_mm_context_id_offset_from_mm(mm);
    if (offset >= 0) {
        mm_context_id_offset = offset;
        return 0;
    }

    /* Will retry at prctl time when in user process context */
    pr_info("wxshadow: context.id scan deferred to first prctl call\n");
    return -1;
}

/* ========== Debug: print tasks list ========== */

void debug_print_tasks_list(int max_count)
{
    struct task_struct *p;
    int count = 0;

    pr_info("wxshadow: === DEBUG: tasks list (first %d processes) ===\n", max_count);
    pr_info("wxshadow: task_struct_offset addr: %px\n", &task_struct_offset);
    pr_info("wxshadow: task_struct_offset: tasks=0x%x (%d), comm=0x%x (%d), mm=0x%x (%d)\n",
            (unsigned short)task_struct_offset.tasks_offset, task_struct_offset.tasks_offset,
            (unsigned short)task_struct_offset.comm_offset, task_struct_offset.comm_offset,
            (unsigned short)task_struct_offset.mm_offset, task_struct_offset.mm_offset);
    pr_info("wxshadow: pid/tgid: using wxfunc(__task_pid_nr_ns)\n");

    pr_info("wxshadow: wx_init_task = %px\n", wx_init_task);

    if (task_struct_offset.tasks_offset < 0 ||
        task_struct_offset.comm_offset < 0) {
        pr_err("wxshadow: tasks_offset (%d) or comm_offset (%d) not initialized!\n",
               task_struct_offset.tasks_offset, task_struct_offset.comm_offset);
        return;
    }

    if (!wx_init_task) {
        pr_err("wxshadow: wx_init_task is NULL!\n");
        return;
    }

    pr_info("wxshadow: wx_init_task (swapper) at %px\n", wx_init_task);

    /* Iterate using wx_next_task() - fixed implementation in wxshadow_internal.h */
    for (p = wx_init_task; (p = wx_next_task(p)) != wx_init_task && count < max_count; ) {
        pid_t pid = 0;
        pid_t tgid = 0;
        const char *comm;
        void *mm = NULL;

        /* Use wxfunc(__task_pid_nr_ns) */
        pid = wxfunc(__task_pid_nr_ns)(p, PIDTYPE_PID, NULL);
        tgid = wxfunc(__task_pid_nr_ns)(p, PIDTYPE_TGID, NULL);

        /* Use get_task_comm helper from linux/sched.h */
        comm = get_task_comm(p);

        if (task_struct_offset.mm_offset >= 0) {
            safe_read_ptr((unsigned long)p + task_struct_offset.mm_offset, &mm);
        }

        pr_info("wxshadow: [%d] task=%px pid=%d tgid=%d mm=%px comm=\"%.16s\"\n",
                count, p, pid, tgid, mm, comm ? comm : "(null)");

        count++;
    }

    pr_info("wxshadow: === END tasks list (%d processes printed) ===\n", count);
}
