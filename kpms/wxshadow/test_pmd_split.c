/*
 * test_pmd_split.c - Test wxshadow PMD split + breakpoint + patch
 *
 * Test 1: Normal function call (baseline)
 * Test 2: SET_BP + SET_REG on THP page (PMD split + breakpoint + reg mod)
 * Test 3: PATCH on THP page (PMD split + code patch + read hiding)
 *
 * Usage: ./test_pmd_split  (wxshadow module must be loaded)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#define PR_WXSHADOW_SET_BP   0x57580001
#define PR_WXSHADOW_SET_REG  0x57580002
#define PR_WXSHADOW_DEL_BP   0x57580003
#define PR_WXSHADOW_PATCH    0x57580006
#define PR_WXSHADOW_RELEASE  0x57580008

#define PMD_SIZE (2UL * 1024 * 1024)

#ifndef MADV_HUGEPAGE
#define MADV_HUGEPAGE 14
#endif

typedef unsigned long (*func_t)(void);

static int check_thp(void *addr)
{
    FILE *f;
    char line[256];
    unsigned long target = (unsigned long)addr;
    unsigned long vma_start, vma_end;
    int in_range = 0;

    f = fopen("/proc/self/smaps", "r");
    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%lx-%lx", &vma_start, &vma_end) == 2)
            in_range = (target >= vma_start && target < vma_end);
        if (in_range && strstr(line, "AnonHugePages:")) {
            unsigned long thp_kb = 0;
            sscanf(line, " AnonHugePages: %lu kB", &thp_kb);
            fclose(f);
            return (int)thp_kb;
        }
    }
    fclose(f);
    return 0;
}

/*
 * Allocate a 2MB THP-backed region, write a function into it.
 * Function: mov x0, #1; ret  (returns 1)
 * Returns aligned base address, or NULL on failure.
 * *out_raw receives the raw mmap pointer for munmap.
 */
static void *alloc_thp_func(void **out_raw)
{
    void *raw, *aligned;
    unsigned int *code;
    int i, thp_kb;

    /* Allocate RW only — PROT_EXEC can prevent THP allocation */
    raw = mmap(NULL, PMD_SIZE * 2,
               PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw == MAP_FAILED)
        return NULL;

    aligned = (void *)(((unsigned long)raw + PMD_SIZE - 1) & ~(PMD_SIZE - 1));
    madvise(aligned, PMD_SIZE, MADV_HUGEPAGE);

    /* Fill with NOP, put function at start */
    code = (unsigned int *)aligned;
    for (i = 0; i < (int)(PMD_SIZE / 4); i++)
        code[i] = 0xd503201f;  /* NOP */

    code[0] = 0xd2800020;  /* mov x0, #1 */
    code[1] = 0xd65f03c0;  /* ret */

    /* Wait for THP before adding PROT_EXEC */
    thp_kb = check_thp(aligned);
    if (thp_kb < 2048) {
        printf("  Waiting 15s for khugepaged...\n");
        sleep(15);
        thp_kb = check_thp(aligned);
    }
    if (thp_kb < 2048) {
        printf("  No THP backing, cannot test.\n");
        munmap(raw, PMD_SIZE * 2);
        return NULL;
    }

    printf("  THP: %d kB (active)\n", thp_kb);

    /* Now add PROT_EXEC — this may or may not split the PMD */
    mprotect(aligned, PMD_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
    __builtin___clear_cache((char *)aligned, (char *)aligned + PMD_SIZE);

    thp_kb = check_thp(aligned);
    printf("  THP after mprotect +exec: %d kB\n", thp_kb);

    *out_raw = raw;
    return aligned;
}

static int test_bp(void)
{
    void *raw, *aligned;
    unsigned long func_addr;
    unsigned long rv;
    int ret, thp_kb;

    printf("--- Test: SET_BP + SET_REG on THP page ---\n");

    aligned = alloc_thp_func(&raw);
    if (!aligned) return 1;
    func_addr = (unsigned long)aligned;

    /* Normal call */
    rv = ((func_t)func_addr)();
    printf("  normal call:  func() = 0x%lx %s\n", rv, rv == 1 ? "OK" : "FAIL");
    if (rv != 1) goto fail;

    /* Set bp on RET, modify x0 */
    ret = prctl(PR_WXSHADOW_SET_BP, 0, func_addr + 4, 0, 0);
    printf("  SET_BP ret:   %d\n", ret);
    if (ret) goto fail;

    thp_kb = check_thp(aligned);
    printf("  THP after bp: %d kB %s\n", thp_kb,
           thp_kb == 0 ? "(split OK)" : "(NOT split?)");

    ret = prctl(PR_WXSHADOW_SET_REG, 0, func_addr + 4, 0, 0x42);
    printf("  SET_REG ret:  %d\n", ret);

    rv = ((func_t)func_addr)();
    printf("  bp call:      func() = 0x%lx %s\n", rv,
           rv == 0x42 ? "PASS" : "FAIL");

    prctl(PR_WXSHADOW_DEL_BP, 0, func_addr + 4, 0, 0);
    munmap(raw, PMD_SIZE * 2);
    return rv != 0x42;

fail:
    munmap(raw, PMD_SIZE * 2);
    return 1;
}

static int test_patch(void)
{
    void *raw, *aligned;
    unsigned long func_addr;
    unsigned long rv;
    int ret, thp_kb;

    /*
     * Patch "mov x0, #1" -> "mov x0, #0x99" at func entry.
     * mov x0, #0x99 = 0xd2801320
     *
     * After PATCH, execution runs shadow (patched) code.
     * Reading memory should show original code (read hiding).
     */
    unsigned int patch_insn = 0xd2801320;  /* mov x0, #0x99 */

    printf("\n--- Test: PATCH on THP page ---\n");

    aligned = alloc_thp_func(&raw);
    if (!aligned) return 1;
    func_addr = (unsigned long)aligned;

    /* Normal call — baseline */
    rv = ((func_t)func_addr)();
    printf("  normal call:  func() = 0x%lx %s\n", rv, rv == 1 ? "OK" : "FAIL");
    if (rv != 1) goto fail;

    /* PATCH first instruction */
    ret = prctl(PR_WXSHADOW_PATCH, 0, func_addr,
                (unsigned long)&patch_insn, sizeof(patch_insn));
    printf("  PATCH ret:    %d\n", ret);
    if (ret) goto fail;

    thp_kb = check_thp(aligned);
    printf("  THP after:    %d kB %s\n", thp_kb,
           thp_kb == 0 ? "(split OK)" : "(NOT split?)");

    /* Execute patched code */
    rv = ((func_t)func_addr)();
    printf("  patched call: func() = 0x%lx %s\n", rv,
           rv == 0x99 ? "PASS (executes patched code)" : "FAIL");
    if (rv != 0x99) goto release;

    /* Read hiding: reading the code should show the original instruction */
    {
        volatile unsigned int *p = (volatile unsigned int *)func_addr;
        unsigned int read_val = *p;
        printf("  read code:    0x%08x %s\n", read_val,
               read_val == 0xd2800020 ? "PASS (sees original, hidden)" :
               read_val == 0xd2801320 ? "FAIL (sees patched, NOT hidden)" :
                                        "??? (unexpected value)");
    }

    /* Call again after read (page state may have changed) */
    rv = ((func_t)func_addr)();
    printf("  call after read: func() = 0x%lx %s\n", rv,
           rv == 0x99 ? "PASS (still runs patched)" : "FAIL");

release:
    /* Release shadow — should restore original */
    ret = prctl(PR_WXSHADOW_RELEASE, 0, func_addr, 0, 0);
    printf("  RELEASE ret:  %d\n", ret);

    rv = ((func_t)func_addr)();
    printf("  after release: func() = 0x%lx %s\n", rv,
           rv == 1 ? "PASS (original restored)" : "FAIL");

    munmap(raw, PMD_SIZE * 2);
    return rv != 1;

fail:
    munmap(raw, PMD_SIZE * 2);
    return 1;
}

int main(void)
{
    int fail = 0;

    printf("=== wxshadow PMD split tests ===\n\n");
    {
        FILE *f = fopen("/sys/kernel/mm/transparent_hugepage/enabled", "r");
        if (f) {
            char buf[128];
            if (fgets(buf, sizeof(buf), f))
                printf("THP mode: %s\n", buf);
            fclose(f);
        }
    }

    fail |= test_bp();
    fail |= test_patch();

    printf("\n=== %s ===\n", fail ? "SOME TESTS FAILED" : "ALL TESTS PASSED");
    return fail;
}
