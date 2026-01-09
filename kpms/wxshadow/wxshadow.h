/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * W^X Shadow Memory KPM Module
 * Copyright (C) 2024
 */

#ifndef _KPM_WXSHADOW_H_
#define _KPM_WXSHADOW_H_

#include <ktypes.h>
#include <stdbool.h>

/* Page size constants */
#define PAGE_SHIFT      12
#define PAGE_SIZE       (1UL << PAGE_SHIFT)
#define PAGE_MASK       (~(PAGE_SIZE - 1))

/* prctl options for wxshadow */
#define PR_WXSHADOW_SET_BP      0x57580001  /* WX + 1 */
#define PR_WXSHADOW_SET_REG     0x57580002  /* WX + 2 */
#define PR_WXSHADOW_DEL_BP      0x57580003  /* WX + 3 */
#define PR_WXSHADOW_SET_TLB_MODE 0x57580004 /* WX + 4: Set TLB flush mode */
#define PR_WXSHADOW_GET_TLB_MODE 0x57580005 /* WX + 5: Get TLB flush mode */

/* TLB flush modes */
enum wxshadow_tlb_mode {
    WX_TLB_MODE_AUTO = 0,       /* Auto: use ASID if available, else broadcast */
    WX_TLB_MODE_PRECISE,        /* Precise: use ASID (vale1is) */
    WX_TLB_MODE_BROADCAST,      /* Broadcast: flush all ASIDs (vaale1is) */
    WX_TLB_MODE_FULL,           /* Full: flush entire TLB (vmalle1is) */
};

/* BRK immediate value */
#define WXSHADOW_BRK_IMM        0x007

/* BRK instruction encoding */
#define AARCH64_BREAK_MON       0xd4200000
#define WXSHADOW_BRK_INSN       (AARCH64_BREAK_MON | (WXSHADOW_BRK_IMM << 5))

/* Instruction size */
#define AARCH64_INSN_SIZE       4

/* Page states */
enum wxshadow_state {
    WX_STATE_NONE = 0,      /* No shadow allocated */
    WX_STATE_ORIGINAL,      /* VA mapped to original page (r--) */
    WX_STATE_SHADOW_X,      /* VA mapped to shadow, permission --x */
    WX_STATE_STEPPING,      /* Single-stepping original instruction (r-x) */
};

/* Maximum register modifications per breakpoint */
#define WXSHADOW_MAX_REG_MODS       4

/* Maximum breakpoints per page */
#define WXSHADOW_MAX_BPS_PER_PAGE   16

/* Register modification entry */
struct wxshadow_reg_mod {
    u8 reg_idx;             /* Register index (0-30 for x0-x30, 31=sp) */
    bool enabled;           /* Whether this modification is active */
    u64 value;              /* Value to set */
};

/* Per-breakpoint info */
struct wxshadow_bp {
    unsigned long addr;     /* Breakpoint address */
    bool active;            /* Whether this bp is active */
    struct wxshadow_reg_mod reg_mods[WXSHADOW_MAX_REG_MODS];
    int nr_reg_mods;        /* Number of active register modifications */
};

/* Per-page shadow info (dynamically allocated per breakpoint page) */
/* Note: struct list_head is defined in linux/list.h (KP framework) */
struct wxshadow_page {
    struct list_head list;          /* Linked to global page_list */
    void *mm;                       /* Owner mm (struct mm_struct *) */
    unsigned long page_addr;        /* Page start address (for lookup) */

    unsigned long pfn_original;     /* Original page PFN */
    unsigned long pfn_shadow;       /* Shadow page PFN */
    void *shadow_page;              /* Shadow page kernel VA (for free) */
    enum wxshadow_state state;      /* Current state */
    void *stepping_task;            /* Task currently single-stepping */

    /* Breakpoint info */
    struct wxshadow_bp bps[WXSHADOW_MAX_BPS_PER_PAGE];
    int nr_bps;                     /* Number of breakpoints */
};

/* BRK handler return values */
#define DBG_HOOK_HANDLED    0
#define DBG_HOOK_ERROR      1

/*
 * Hook method selection
 * WX_HOOK_METHOD_DIRECT: hook_wrap brk_handler/single_step_handler directly
 * WX_HOOK_METHOD_REGISTER: use register_user_break_hook/register_user_step_hook API
 */
enum wx_hook_method {
    WX_HOOK_METHOD_NONE = 0,
    WX_HOOK_METHOD_DIRECT,      /* Direct hook (preferred) */
    WX_HOOK_METHOD_REGISTER,    /* register_user_*_hook API (fallback) */
};

/*
 * struct break_hook - for register_user_break_hook API
 * Must match kernel's struct break_hook layout (arch/arm64/include/asm/debug-monitors.h)
 */
struct wx_break_hook {
    struct list_head node;
    int (*fn)(struct pt_regs *regs, unsigned int esr);
    u16 imm;
    u16 mask;
};

/*
 * struct step_hook - for register_user_step_hook API
 * Must match kernel's struct step_hook layout (arch/arm64/include/asm/debug-monitors.h)
 */
struct wx_step_hook {
    struct list_head node;
    int (*fn)(struct pt_regs *regs, unsigned int esr);
};

/* VM fault return values */
#define VM_FAULT_NOPAGE     0x0001
#define VM_FAULT_SIGBUS     0x0002
#define VM_FAULT_RETRY      0x0400

/* Page flags check */
#define PG_anon             0

/* PTE bits - use pgtable.h definitions if available */
#ifndef PTE_VALID
#define PTE_VALID           (1UL << 0)
#endif
#ifndef PTE_TYPE_PAGE
#define PTE_TYPE_PAGE       (3UL << 0)
#endif
#ifndef PTE_USER
#define PTE_USER            (1UL << 6)
#endif
#ifndef PTE_RDONLY
#define PTE_RDONLY          (1UL << 7)
#endif
#ifndef PTE_SHARED
#define PTE_SHARED          (3UL << 8)
#endif
#ifndef PTE_AF
#define PTE_AF              (1UL << 10)
#endif
#ifndef PTE_NG
#define PTE_NG              (1UL << 11)
#endif
#ifndef PTE_PXN
#define PTE_PXN             (1UL << 53)
#endif
#ifndef PTE_UXN
#define PTE_UXN             (1UL << 54)
#endif
#ifndef PTE_WRITE
#define PTE_WRITE           (1UL << 51)
#endif

/* Memory attribute index for normal memory */
#ifndef PTE_ATTRINDX_NORMAL
#define PTE_ATTRINDX_NORMAL (0UL << 2)
#endif

#endif /* _KPM_WXSHADOW_H_ */
