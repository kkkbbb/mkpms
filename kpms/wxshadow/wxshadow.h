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
#define PR_WXSHADOW_PATCH       0x57580006  /* WX + 6: Patch shadow page via kernel VA */
#define PR_WXSHADOW_RELEASE     0x57580008  /* WX + 8: Release shadow */

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
    WX_STATE_DORMANT,       /* Hook retired; VA restored to original, shadow kept */
};

/* Maximum register modifications per breakpoint */
#define WXSHADOW_MAX_REG_MODS       4

/* Maximum breakpoints per page */
#define WXSHADOW_MAX_BPS_PER_PAGE   16
#define WXSHADOW_MAX_PATCHES_PER_PAGE 32
#define WXSHADOW_MAX_ACTIVE_MODS_PER_PAGE \
    (WXSHADOW_MAX_BPS_PER_PAGE + WXSHADOW_MAX_PATCHES_PER_PAGE)
#define WXSHADOW_DIRTY_WORD_BITS    (sizeof(unsigned long) * 8)
#define WXSHADOW_DIRTY_BITMAP_WORDS \
    ((PAGE_SIZE + WXSHADOW_DIRTY_WORD_BITS - 1) / WXSHADOW_DIRTY_WORD_BITS)

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
    u64 serial;             /* Last write order on shadow page */
    struct wxshadow_reg_mod reg_mods[WXSHADOW_MAX_REG_MODS];
    int nr_reg_mods;        /* Number of active register modifications */
};

struct wxshadow_patch {
    u16 offset;             /* Patch start offset within page */
    u16 len;                /* Patch length in bytes */
    bool active;            /* Whether this patch record is active */
    u64 serial;             /* Last write order on shadow page */
    void *data;             /* Patched bytes, len bytes */
};

/* Per-page shadow info (dynamically allocated per breakpoint page) */
/* Note: struct list_head is defined in linux/list.h (KP framework) */
struct wxshadow_page {
    struct list_head list;          /* Linked to global page_list */
    void *mm;                       /* Owner mm (struct mm_struct *) */
    unsigned long page_addr;        /* Page start address (for lookup) */

    unsigned long pfn_original;     /* Original page PFN */
    u64 pte_original;               /* Original user PTE snapshot */
    unsigned long pfn_shadow;       /* Shadow page PFN */
    void *shadow_page;              /* Shadow page kernel VA (for free) */
    enum wxshadow_state state;      /* Current state */
    void *stepping_task;            /* Task currently single-stepping */
    int brk_in_flight;              /* BRK handlers between trap and STEPPING */

    /*
     * Lifecycle fields (protected by global_lock):
     *   refcount: 1 while in page_list (list's ref); each find_page/find_by_addr
     *             caller increments before releasing the lock and must call
     *             wxshadow_page_put() when done.  Struct is kfree'd when it
     *             reaches 0.
     *   dead:     set to true when the page is removed from page_list.
     *             Handlers that obtained a ref before removal must check this
     *             flag and skip any PTE-switch-to-shadow operations.
     *   release_pending:
     *             set when user/module teardown arrives while a task is in the
     *             STEPPING state.  The page stays in page_list so the step
     *             handler can finalize the teardown after the original
     *             instruction retires.
     *   logical_release_pending:
     *             set when a user-facing release wants to retire the hook
     *             without tearing down the page.  The step handler switches the
     *             page into DORMANT once the original instruction retires.
     *   fork_paused:
     *             set while copy_process is cloning the parent's mm.  The
     *             parent PTE is temporarily restored to the original page so
     *             the child never inherits the shadow PFN; after copy_process
     *             returns, the parent mapping is switched back to shadow.
     */
    int  refcount;
    bool dead;
    bool release_pending;
    bool logical_release_pending;
    bool fork_paused;
    atomic_t pte_lock;            /* Serializes PTE rewrites for this page */

    /* Breakpoint info */
    struct wxshadow_bp bps[WXSHADOW_MAX_BPS_PER_PAGE];
    int nr_bps;                     /* Number of breakpoints */
    struct wxshadow_patch patches[WXSHADOW_MAX_PATCHES_PER_PAGE];
    int nr_patches;                 /* Number of patch records */
    u64 next_mod_serial;            /* Monotonic shadow write serial */
    unsigned long bp_dirty[WXSHADOW_DIRTY_BITMAP_WORDS];
    unsigned long patch_dirty[WXSHADOW_DIRTY_BITMAP_WORDS];
};

/* BRK handler return values */
#define DBG_HOOK_HANDLED    0
#define DBG_HOOK_ERROR      1

/* Hook method selection */
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
#ifndef PTE_UXN
#define PTE_UXN             (1UL << 54)
#endif
/* Memory attribute index for normal memory */
#ifndef PTE_ATTRINDX_NORMAL
#define PTE_ATTRINDX_NORMAL (0UL << 2)
#endif

#endif /* _KPM_WXSHADOW_H_ */
