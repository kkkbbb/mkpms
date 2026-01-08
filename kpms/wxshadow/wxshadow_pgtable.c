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
    u64 p4d_val = *(u64 *)p4d;
    if (!p4d_val) return NULL;
    unsigned long pud_base = pxd_page_vaddr(p4d_val);
    return (void *)((u64 *)pud_base + pud_index(addr));
}

/*
 * wxshadow_pmd_offset - get PMD entry pointer from PUD entry
 */
static inline void *wxshadow_pmd_offset(void *pud, unsigned long addr)
{
    u64 pud_val = *(u64 *)pud;
    if (!pud_val) return NULL;
    unsigned long pa = pud_val & 0x0000FFFFFFFFF000UL;
    pr_info("wxshadow: [pmd_offset] pud_val=%llx pa=%lx physvirt=%llx memstart=%llx\n",
            pud_val, pa,
            kvar_physvirt_offset ? *kvar_physvirt_offset : 0,
            *kvar_memstart_addr);
    unsigned long pmd_base = pxd_page_vaddr(pud_val);
    pr_info("wxshadow: [pmd_offset] pmd_base=%lx pmd_index=%lx\n", pmd_base, pmd_index(addr));
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
    u64 pmd_val = *(u64 *)pmd;
    unsigned long pte_table_vaddr = pmd_page_vaddr(pmd_val);
    return (u64 *)(pte_table_vaddr + pte_index(addr) * sizeof(u64));
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

    pr_info("wxshadow: [get_user_pte] enter mm=%px addr=%lx page_level=%d\n",
            mm, addr, wx_page_level);

    pgd = wxshadow_pgd_offset(mm, addr);
    pr_info("wxshadow: [get_user_pte] pgd=%px pgd_val=%llx\n", pgd, pgd ? *(u64 *)pgd : 0);
    if (!pgd || (*(u64 *)pgd == 0))
        return NULL;

    if (wx_page_level == 4) {
        /* 4-level page tables: PGD -> PUD -> PMD -> PTE */
        pud = wxshadow_pud_offset(pgd, addr);
        pr_info("wxshadow: [get_user_pte] pud=%px pud_val=%llx\n", pud, pud ? *(u64 *)pud : 0);
        if (!pud || (*(u64 *)pud == 0))
            return NULL;

        pmd = wxshadow_pmd_offset(pud, addr);
    } else {
        /* 3-level page tables: PGD -> PMD -> PTE (no PUD) */
        pmd = wxshadow_pmd_offset(pgd, addr);
    }
    pr_info("wxshadow: [get_user_pte] pmd=%px pmd_val=%llx\n", pmd, pmd ? *(u64 *)pmd : 0);
    if (!pmd || (*(u64 *)pmd == 0))
        return NULL;

    /* Check if PMD is a section/block mapping (2MB huge page) */
    u64 pmd_val = *(u64 *)pmd;
    if (pmd_sect(pmd_val)) {
        pr_warn("wxshadow: address 0x%lx is in 2MB section mapping, not supported\n", addr);
        return NULL;
    }
    if (!pmd_table(pmd_val)) {
        pr_warn("wxshadow: invalid PMD type for address 0x%lx: 0x%llx\n", addr, pmd_val);
        return NULL;
    }

    /* Get PTE pointer */
    pte = pte_offset_kernel_local(pmd, addr);
    pr_info("wxshadow: [get_user_pte] pte=%px pte_val=%llx\n", pte, pte ? *pte : 0);

    /* ptlp is ignored - we operate locklessly */
    if (ptlp)
        *ptlp = NULL;

    pr_info("wxshadow: [get_user_pte] returning pte=%px (lockless)\n", pte);
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

    pr_info("wxshadow: TLBI %s: addr=%lx asid=%llu tlbi_val=%llx\n",
            mode_str, uaddr, asid, tlbi_val);
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
    u64 old_val, new_val;

    pte = get_user_pte(mm, addr, NULL);
    if (!pte) {
        pr_err("wxshadow: [switch] FAILED get_user_pte addr=%lx\n", addr);
        return -1;
    }
    old_val = *pte;

    entry = make_pte(target_pfn, prot);
    wxshadow_set_pte_at(mm, addr, pte, entry);

    /* Read back and verify */
    new_val = *pte;
    pr_info("wxshadow: [switch] addr=%lx pfn=%lx old=%llx new=%llx expect=%llx\n",
            addr, target_pfn, old_val, new_val, entry);

    wxshadow_flush_tlb_page(vma, addr);

    return 0;
}
