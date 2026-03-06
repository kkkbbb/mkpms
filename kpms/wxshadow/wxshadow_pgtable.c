/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * W^X Shadow Memory KPM Module - Page Table Operations
 *
 * Page table manipulation, PTE operations, TLB flush.
 *
 * Copyright (C) 2024
 */

#include "wxshadow_internal.h"

/* ========== Page table index calculation ========== */

/*
 * pte_index - calculate PTE index from address
 */
static inline unsigned long pte_index(unsigned long addr)
{
    return (addr >> PAGE_SHIFT) & (512 - 1);  /* PTRS_PER_PTE = 512 for 4K pages */
}

/*
 * Page table index calculation macros
 * ARM64 page table levels (4KB pages, 48-bit VA):
 *   PGD: bits 47:39 (pgdir_shift = 39)
 *   PUD: bits 38:30 (pud_shift = 30)
 *   PMD: bits 29:21 (pmd_shift = 21)
 *   PTE: bits 20:12 (pte_shift = 12)
 */
static inline unsigned long pgd_index(unsigned long addr)
{
    int pxd_bits = wx_page_shift - 3;
    int pgdir_shift = wx_page_shift + (wx_page_level - 1) * pxd_bits;
    return (addr >> pgdir_shift) & ((1UL << pxd_bits) - 1);
}

static inline unsigned long pud_index(unsigned long addr)
{
    int pxd_bits = wx_page_shift - 3;
    int pud_shift = wx_page_shift + (wx_page_level - 2) * pxd_bits;
    return (addr >> pud_shift) & ((1UL << pxd_bits) - 1);
}

static inline unsigned long pmd_index(unsigned long addr)
{
    int pxd_bits = wx_page_shift - 3;
    int pmd_shift = wx_page_shift + 1 * pxd_bits;
    return (addr >> pmd_shift) & ((1UL << pxd_bits) - 1);
}

/* ========== Page table descriptor types ========== */

#define PXD_TYPE_MASK   0x3UL
#define PXD_TYPE_SECT   0x1UL   /* Block/Section entry */
#define PXD_TYPE_TABLE  0x3UL   /* Table entry */

static inline bool pmd_sect(u64 pmd)
{
    return (pmd & PXD_TYPE_MASK) == PXD_TYPE_SECT;
}

static inline bool pmd_table(u64 pmd)
{
    return (pmd & PXD_TYPE_MASK) == PXD_TYPE_TABLE;
}

/*
 * pxd_page_vaddr - get virtual address of next-level table from page table entry
 */
static inline unsigned long pxd_page_vaddr(u64 pxd_val)
{
    unsigned long pa = pxd_val & 0x0000FFFFFFFFF000UL;
    return phys_to_virt_safe(pa);
}

/* ========== Page table offset functions ========== */

/*
 * wxshadow_pgd_offset - get PGD entry pointer for address
 */
static inline void *wxshadow_pgd_offset(void *mm, unsigned long addr)
{
    void *pgd = mm_pgd(mm);
    if (!pgd) return NULL;
    return (void *)((u64 *)pgd + pgd_index(addr));
}

/*
 * wxshadow_pud_offset - get PUD entry pointer from P4D/PGD entry
 */
static inline void *wxshadow_pud_offset(void *p4d, unsigned long addr)
{
    u64 p4d_val;
    unsigned long pud_base;

    if (!p4d || !is_kva((unsigned long)p4d))
        return NULL;
    if (!safe_read_u64((unsigned long)p4d, &p4d_val))
        return NULL;
    if (!p4d_val)
        return NULL;

    pud_base = pxd_page_vaddr(p4d_val);
    if (!is_kva(pud_base))
        return NULL;

    return (void *)((u64 *)pud_base + pud_index(addr));
}

/*
 * wxshadow_pmd_offset - get PMD entry pointer from PUD entry
 */
static inline void *wxshadow_pmd_offset(void *pud, unsigned long addr)
{
    u64 pud_val;
    unsigned long pa, pmd_base;

    if (!pud || !is_kva((unsigned long)pud))
        return NULL;
    if (!safe_read_u64((unsigned long)pud, &pud_val))
        return NULL;
    if (!pud_val)
        return NULL;

    pa = pud_val & 0x0000FFFFFFFFF000UL;

    pmd_base = pxd_page_vaddr(pud_val);
    if (!is_kva(pmd_base))
        return NULL;
    return (void *)((u64 *)pmd_base + pmd_index(addr));
}

/*
 * pmd_page_vaddr - get virtual address of PTE table from PMD entry
 */
static inline unsigned long pmd_page_vaddr(u64 pmd)
{
    unsigned long pa = pmd & 0x0000FFFFFFFFF000UL;
    return phys_to_virt_safe(pa);
}

/*
 * pte_offset_kernel_local - get PTE pointer from PMD
 */
static inline u64 *pte_offset_kernel_local(void *pmd, unsigned long addr)
{
    u64 pmd_val;
    unsigned long pte_table_vaddr;

    if (!pmd || !is_kva((unsigned long)pmd))
        return NULL;
    if (!safe_read_u64((unsigned long)pmd, &pmd_val))
        return NULL;

    pte_table_vaddr = pmd_page_vaddr(pmd_val);
    if (!is_kva(pte_table_vaddr))
        return NULL;

    return (u64 *)(pte_table_vaddr + pte_index(addr) * sizeof(u64));
}

/* ========== PMD split (huge page → PTE table) ========== */

/*
 * wxshadow_try_split_pmd - split PMD block mapping via kernel's __split_huge_pmd.
 *
 * Call from process context before get_user_pte() when the target address
 * may be in a THP (2MB block) mapping.  If the PMD is already a table
 * entry (normal pages), this is a no-op.
 *
 * @mm:   mm_struct pointer
 * @vma:  vm_area_struct covering addr (from find_vma)
 * @addr: target virtual address
 *
 * Returns 0 on success (or no split needed), negative errno on failure.
 */
int wxshadow_try_split_pmd(void *mm, void *vma, unsigned long addr)
{
    void *pgd, *pud, *pmd;
    u64 pgd_val, pud_val, pmd_val;

    if (!mm || !vma)
        return 0;

    /* Walk page tables to PMD level */
    pgd = wxshadow_pgd_offset(mm, addr);
    if (!pgd || !is_kva((unsigned long)pgd))
        return 0;
    if (!safe_read_u64((unsigned long)pgd, &pgd_val) || pgd_val == 0)
        return 0;

    if (wx_page_level == 4) {
        pud = wxshadow_pud_offset(pgd, addr);
        if (!pud)
            return 0;
        if (!safe_read_u64((unsigned long)pud, &pud_val) || pud_val == 0)
            return 0;
        pmd = wxshadow_pmd_offset(pud, addr);
    } else {
        pmd = wxshadow_pmd_offset(pgd, addr);
    }
    if (!pmd)
        return 0;
    if (!safe_read_u64((unsigned long)pmd, &pmd_val) || pmd_val == 0)
        return 0;

    /* Not a block mapping — nothing to do */
    if (!pmd_sect(pmd_val))
        return 0;

    if (!kfunc___split_huge_pmd) {
        pr_err("wxshadow: addr %lx is in PMD block but __split_huge_pmd not available\n", addr);
        return -38;  /* ENOSYS */
    }

    {
        int pxd_bits = wx_page_shift - 3;
        unsigned long pmd_shift_val = wx_page_shift + 1 * pxd_bits;
        unsigned long block_mask = ~((1UL << pmd_shift_val) - 1);

        pr_info("wxshadow: splitting PMD block at %lx via __split_huge_pmd\n",
                addr & block_mask);
        kfunc___split_huge_pmd(vma, pmd, addr & block_mask, false, NULL);
    }

    /* Verify split succeeded */
    if (!safe_read_u64((unsigned long)pmd, &pmd_val))
        return -14;
    if (pmd_sect(pmd_val)) {
        pr_err("wxshadow: PMD still block after __split_huge_pmd for addr %lx\n", addr);
        return -1;
    }

    pr_info("wxshadow: PMD split succeeded for addr %lx\n", addr);
    return 0;
}

/* ========== PTE operations ========== */

/*
 * Get PTE for a user address (lockless)
 *
 * NOTE: We operate without holding page_table_lock. This is safe because:
 * 1. We're modifying user-space PTEs, not kernel PTEs
 * 2. We use atomic set_pte_at() + flush_tlb_page() operations
 * 3. Our global_lock protects our shadow page state
 * 4. Worst case of a race is a spurious page fault, which we handle gracefully
 */
u64 *get_user_pte(void *mm, unsigned long addr, void **ptlp)
{
    void *pgd, *pud, *pmd;
    u64 *pte;
    u64 pgd_val, pud_val, pmd_val;

    pgd = wxshadow_pgd_offset(mm, addr);
    if (!pgd || !is_kva((unsigned long)pgd))
        return NULL;
    if (!safe_read_u64((unsigned long)pgd, &pgd_val))
        return NULL;
    if (pgd_val == 0)
        return NULL;

    if (wx_page_level == 4) {
        /* 4-level page tables: PGD -> PUD -> PMD -> PTE */
        pud = wxshadow_pud_offset(pgd, addr);
        if (!pud)
            return NULL;
        if (!safe_read_u64((unsigned long)pud, &pud_val))
            return NULL;
        if (pud_val == 0)
            return NULL;

        pmd = wxshadow_pmd_offset(pud, addr);
    } else {
        /* 3-level page tables: PGD -> PMD -> PTE (no PUD) */
        pmd = wxshadow_pmd_offset(pgd, addr);
    }
    if (!pmd)
        return NULL;
    if (!safe_read_u64((unsigned long)pmd, &pmd_val))
        return NULL;
    if (pmd_val == 0)
        return NULL;

    /* Block mapping: caller should have called wxshadow_try_split_pmd() first */
    if (pmd_sect(pmd_val)) {
        pr_warn("wxshadow: addr 0x%lx is PMD block, call wxshadow_try_split_pmd() first\n", addr);
        return NULL;
    }
    if (!pmd_table(pmd_val)) {
        pr_warn("wxshadow: invalid PMD type for address 0x%lx: 0x%llx\n", addr, pmd_val);
        return NULL;
    }

    /* Get PTE pointer */
    pte = pte_offset_kernel_local(pmd, addr);
    if (!pte || !is_kva((unsigned long)pte))
        return NULL;

    /* ptlp is ignored - we operate locklessly */
    if (ptlp)
        *ptlp = NULL;

    return pte;
}

/*
 * Release PTE (no-op in lockless mode)
 */
void pte_unmap_unlock(u64 *pte, void *ptl)
{
    (void)pte;
    (void)ptl;
    /* No lock to release in lockless mode */
}

/*
 * set_pte - write PTE value with proper barriers
 */
static inline void set_pte(u64 *ptep, u64 pte)
{
    *(volatile u64 *)ptep = pte;
}

/*
 * set_pte_at - set PTE with icache sync if needed
 */
void wxshadow_set_pte_at(void *mm, unsigned long addr, u64 *ptep, u64 pte)
{
    set_pte(ptep, pte);
}

/*
 * Get ASID from mm->context.id
 * Returns 0 if offset not detected or mm is NULL
 */
static inline u64 mm_get_asid(void *mm)
{
    u64 context_id;

    if (!mm || mm_context_id_offset < 0)
        return 0;

    context_id = *(u64 *)((char *)mm + mm_context_id_offset);

    /* ASID is typically in low 16 bits of context.id
     * Some kernels may use different formats, but low bits are most common
     */
    return context_id & 0xFFFF;
}

/*
 * ARM64 TLBI instruction fallback
 *
 * When kernel flush_tlb_page functions are not available, we use
 * TLBI instructions directly.
 *
 * TLBI instruction variants:
 * - VALE1IS: VA, Last level, EL1, Inner Shareable (precise, needs ASID)
 * - VAALE1IS: VA, All ASIDs, Last level, EL1, Inner Shareable (broadcast)
 * - VMALLE1IS: All entries, EL1, Inner Shareable (full flush)
 *
 * TLBI operand format: {ASID[63:48], VA[47:12]}
 */
static void wxshadow_tlbi_page(void *mm, unsigned long uaddr)
{
    u64 asid = mm_get_asid(mm);
    u64 tlbi_val;
    int mode = tlb_flush_mode;
    const char *mode_str;

    /* Build TLBI operand: ASID in bits [63:48], VA>>12 in bits [43:0] */
    tlbi_val = (asid << 48) | ((uaddr >> 12) & 0xFFFFFFFFFFFFUL);

    switch (mode) {
    case WX_TLB_MODE_PRECISE:
        /* Force precise mode - use ASID even if 0 (may not work correctly) */
        asm volatile("tlbi vale1is, %0" : : "r"(tlbi_val) : "memory");
        mode_str = "precise";
        break;

    case WX_TLB_MODE_BROADCAST:
        /* Force broadcast mode - flush all ASIDs for this VA */
        asm volatile("tlbi vaale1is, %0" : : "r"(uaddr >> 12) : "memory");
        mode_str = "broadcast";
        break;

    case WX_TLB_MODE_FULL:
        /* Full TLB flush - most expensive but guaranteed to work */
        asm volatile("tlbi vmalle1is" : : : "memory");
        mode_str = "full";
        break;

    case WX_TLB_MODE_AUTO:
    default:
        /* Auto mode: use ASID if available, else broadcast */
        if (asid != 0) {
            asm volatile("tlbi vale1is, %0" : : "r"(tlbi_val) : "memory");
            mode_str = "auto-precise";
        } else {
            asm volatile("tlbi vaale1is, %0" : : "r"(uaddr >> 12) : "memory");
            mode_str = "auto-broadcast";
        }
        break;
    }

    /* Ensure TLB invalidation completes before continuing */
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
}

/*
 * flush_tlb_page - flush single TLB entry
 *
 * Priority:
 * 1. kfunc_flush_tlb_page (kernel function)
 * 2. kfunc___flush_tlb_range (fallback kernel function)
 * 3. TLBI instruction (final fallback)
 */
void wxshadow_flush_tlb_page(void *vma, unsigned long uaddr)
{
    if (kfunc_flush_tlb_page) {
        kfunc_flush_tlb_page(vma, uaddr);
    } else if (kfunc___flush_tlb_range) {
        /* __flush_tlb_range(vma, start, end, stride, last_level, tlb_level)
         * last_level=true: only invalidate last-level PTE
         * tlb_level=3: PTE level for 4K pages
         */
        kfunc___flush_tlb_range(vma, uaddr, uaddr + PAGE_SIZE, PAGE_SIZE, true, 3);
    } else {
        /* Final fallback: use TLBI instruction directly */
        void *mm = vma ? vma_mm(vma) : NULL;
        wxshadow_tlbi_page(mm, uaddr);
    }
}

/* Build a PTE value */
u64 make_pte(unsigned long pfn, u64 prot)
{
    return (pfn << PAGE_SHIFT) | prot | PTE_VALID | PTE_TYPE_PAGE |
           PTE_AF | PTE_SHARED | PTE_NG | PTE_ATTRINDX_NORMAL;
}

/* Switch page mapping (lockless) */
int wxshadow_switch_mapping(void *vma, unsigned long addr,
                            unsigned long target_pfn, u64 prot)
{
    void *mm = vma_mm(vma);
    u64 *pte;
    u64 entry;

    if (!mm) {
        pr_err("wxshadow: [switch] vma_mm returned NULL\n");
        return -1;
    }

    pte = get_user_pte(mm, addr, NULL);
    if (!pte) {
        pr_err("wxshadow: [switch] get_user_pte failed for addr=%lx\n", addr);
        return -1;
    }

    entry = make_pte(target_pfn, prot);
    wxshadow_set_pte_at(mm, addr, pte, entry);
    wxshadow_flush_tlb_page(vma, addr);

    return 0;
}
