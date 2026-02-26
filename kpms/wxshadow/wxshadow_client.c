/*
 * wxshadow_client - W^X Shadow Memory Client Tool
 *
 * Usage:
 *   wxshadow_client -p <pid> -a <addr>              # Set breakpoint
 *   wxshadow_client -p <pid> -a <addr> -r x0=1     # Set bp with reg mod
 *   wxshadow_client -p <pid> -a <addr> -d          # Delete breakpoint at addr
 *   wxshadow_client -p <pid> -d                    # Delete ALL breakpoints
 *   wxshadow_client -p <pid> -b <lib> -o <offset>  # Use lib+offset
 *   wxshadow_client -p <pid> -m                    # Show maps
 *   wxshadow_client -p <pid> --release             # Release ALL shadows
 *   wxshadow_client --selftest                     # Run self-test
 *
 * Copyright (C) 2024
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <errno.h>
#include <getopt.h>
#include <ctype.h>

/* prctl options for wxshadow */
#define PR_WXSHADOW_SET_BP      0x57580001
#define PR_WXSHADOW_SET_REG     0x57580002
#define PR_WXSHADOW_DEL_BP      0x57580003
#define PR_WXSHADOW_PATCH       0x57580006
#define PR_WXSHADOW_RELEASE     0x57580008

#define MAX_REG_MODS 4

struct reg_mod {
    int reg_idx;
    unsigned long value;
};

static void print_usage(const char *prog) {
    printf("wxshadow_client - W^X Shadow Memory Client\n\n");
    printf("Usage:\n");
    printf("  %s -p <pid> -a <addr>                 Set breakpoint\n", prog);
    printf("  %s -p <pid> -a <addr> -r x0=<val>     Set bp with register modification\n", prog);
    printf("  %s -p <pid> -a <addr> -d              Delete breakpoint at addr\n", prog);
    printf("  %s -p <pid> -d                        Delete ALL breakpoints\n", prog);
    printf("  %s -p <pid> -b <lib> -o <offset>      Use library + offset\n", prog);
    printf("  %s -p <pid> -m                        Show executable maps\n", prog);
    printf("  %s -p <pid> -a <addr> --patch <hex>   Patch shadow page\n", prog);
    printf("  %s -p <pid> -a <addr> --release       Release shadow at addr\n", prog);
    printf("  %s -p <pid> --release                 Release ALL shadows\n", prog);
    printf("\nOptions:\n");
    printf("  -p, --pid <pid>       Target process ID (0 for self)\n");
    printf("  -a, --addr <addr>     Virtual address (hex, optional for -d/--release)\n");
    printf("  -b, --base <lib>      Library name to find base address\n");
    printf("  -o, --offset <off>    Offset from library base (hex)\n");
    printf("  -r, --reg <reg>=<val> Register modification (can use multiple times)\n");
    printf("                        reg: x0-x30 or sp\n");
    printf("  -d, --delete          Delete breakpoint (all if no addr specified)\n");
    printf("  -m, --maps            Show executable memory regions\n");
    printf("  --patch <hex>         Patch shadow page with hex data (e.g. d503201f)\n");
    printf("  --release             Release shadow (all if no addr specified)\n");
    printf("  -t, --selftest        Run self-test (set BP/patch on self)\n");
    printf("  -h, --help            Show this help\n");
    printf("\nExamples:\n");
    printf("  %s -p 1234 -a 0x7b5c001234\n", prog);
    printf("  %s -p 1234 -b libc.so -o 0x12345 -r x0=0\n", prog);
    printf("  %s -p 1234 -a 0x7b5c001234 -r x0=1 -r x1=0x100\n", prog);
    printf("  %s -p 1234 -m\n", prog);
    printf("  %s -p 1234 -a 0x7b5c001234 --patch d503201f\n", prog);
    printf("  %s -p 1234 -a 0x7b5c001234 --release\n", prog);
    printf("  %s -p 1234 -d                          # delete all BPs\n", prog);
    printf("  %s -p 1234 --release                   # release all shadows\n", prog);
    printf("  %s --selftest                              # run self-test\n", prog);
}

/* Parse register name to index */
static int parse_reg_name(const char *name) {
    if (strcasecmp(name, "sp") == 0)
        return 31;

    if (tolower(name[0]) == 'x') {
        int idx = atoi(name + 1);
        if (idx >= 0 && idx <= 30)
            return idx;
    }

    return -1;
}

/* Parse register modification string like "x0=123" */
static int parse_reg_mod(const char *str, struct reg_mod *mod) {
    char reg_name[16];
    char *eq = strchr(str, '=');

    if (!eq || eq == str)
        return -1;

    size_t name_len = eq - str;
    if (name_len >= sizeof(reg_name))
        return -1;

    strncpy(reg_name, str, name_len);
    reg_name[name_len] = '\0';

    mod->reg_idx = parse_reg_name(reg_name);
    if (mod->reg_idx < 0)
        return -1;

    mod->value = strtoull(eq + 1, NULL, 0);
    return 0;
}

/* Find library base address in /proc/pid/maps */
static unsigned long find_lib_base(pid_t pid, const char *lib_name) {
    char path[256];
    char line[512];
    FILE *fp;

    if (pid == 0)
        snprintf(path, sizeof(path), "/proc/self/maps");
    else
        snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    fp = fopen(path, "r");
    if (!fp) {
        perror("fopen maps");
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, lib_name)) {
            unsigned long start;
            if (sscanf(line, "%lx-", &start) == 1) {
                /* Check if it's executable */
                if (strstr(line, "r-xp") || strstr(line, "r--p")) {
                    fclose(fp);
                    return start;
                }
            }
        }
    }

    fclose(fp);
    return 0;
}

/* Show executable memory regions */
static void show_maps(pid_t pid) {
    char path[256];
    char line[512];
    FILE *fp;

    if (pid == 0)
        snprintf(path, sizeof(path), "/proc/self/maps");
    else
        snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    fp = fopen(path, "r");
    if (!fp) {
        perror("fopen maps");
        return;
    }

    printf("Executable regions for pid %d:\n", pid ? pid : getpid());
    printf("%-18s %-18s %-5s %s\n", "Start", "End", "Perm", "Name");
    printf("------------------------------------------------------------------\n");

    while (fgets(line, sizeof(line), fp)) {
        unsigned long start, end;
        char perms[8];
        char *name;

        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) < 3)
            continue;

        /* Only show executable regions */
        if (perms[2] != 'x')
            continue;

        /* Find name (last field) */
        name = strrchr(line, ' ');
        if (name) {
            name++;
            /* Remove newline */
            char *nl = strchr(name, '\n');
            if (nl) *nl = '\0';
        } else {
            name = "";
        }

        printf("0x%016lx 0x%016lx %-5s %s\n", start, end, perms, name);
    }

    fclose(fp);
}

/* Set breakpoint via prctl */
static int set_breakpoint(pid_t pid, unsigned long addr) {
    int ret = prctl(PR_WXSHADOW_SET_BP, pid, addr, 0, 0);
    if (ret < 0) {
        fprintf(stderr, "prctl(SET_BP) failed: %s (errno=%d)\n",
                strerror(errno), errno);
        return -1;
    }
    printf("Breakpoint set at 0x%lx for pid %d\n", addr, pid ? pid : getpid());
    return 0;
}

/* Set register modification via prctl */
static int set_reg_mod(pid_t pid, unsigned long addr, int reg_idx, unsigned long value) {
    int ret = prctl(PR_WXSHADOW_SET_REG, pid, addr, reg_idx, value);
    if (ret < 0) {
        fprintf(stderr, "prctl(SET_REG) failed: %s (errno=%d)\n",
                strerror(errno), errno);
        return -1;
    }

    if (reg_idx == 31)
        printf("Register modification set: sp = 0x%lx\n", value);
    else
        printf("Register modification set: x%d = 0x%lx\n", reg_idx, value);

    return 0;
}

/* Delete breakpoint via prctl (addr=0 means delete all) */
static int del_breakpoint(pid_t pid, unsigned long addr) {
    int ret = prctl(PR_WXSHADOW_DEL_BP, pid, addr, 0, 0);
    if (ret < 0) {
        fprintf(stderr, "prctl(DEL_BP) failed: %s (errno=%d)\n",
                strerror(errno), errno);
        return -1;
    }
    if (addr == 0)
        printf("All breakpoints deleted for pid %d\n", pid ? pid : getpid());
    else
        printf("Breakpoint deleted at 0x%lx for pid %d\n", addr, pid ? pid : getpid());
    return 0;
}

/* Parse hex string to binary data. Returns number of bytes, or -1 on error */
static int parse_hex_string(const char *hex, unsigned char *out, int max_len) {
    int len = strlen(hex);
    int i, out_len;

    if (len % 2 != 0) {
        fprintf(stderr, "Hex string must have even length\n");
        return -1;
    }

    out_len = len / 2;
    if (out_len > max_len) {
        fprintf(stderr, "Hex data too long (%d bytes, max %d)\n", out_len, max_len);
        return -1;
    }

    for (i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
            fprintf(stderr, "Invalid hex at position %d\n", i * 2);
            return -1;
        }
        out[i] = (unsigned char)byte;
    }

    return out_len;
}

/* Patch shadow page via prctl */
static int patch_shadow(pid_t pid, unsigned long addr,
                        unsigned char *data, int data_len) {
    int ret = prctl(PR_WXSHADOW_PATCH, pid, addr, (unsigned long)data, data_len);
    if (ret < 0) {
        fprintf(stderr, "prctl(PATCH) failed: %s (errno=%d)\n",
                strerror(errno), errno);
        return -1;
    }
    printf("Shadow page patched at 0x%lx (%d bytes) for pid %d\n",
           addr, data_len, pid ? pid : getpid());
    return 0;
}

/* Release shadow page via prctl (addr=0 means release all) */
static int release_shadow(pid_t pid, unsigned long addr) {
    int ret = prctl(PR_WXSHADOW_RELEASE, pid, addr, 0, 0);
    if (ret < 0) {
        fprintf(stderr, "prctl(RELEASE) failed: %s (errno=%d)\n",
                strerror(errno), errno);
        return -1;
    }
    if (addr == 0)
        printf("All shadow pages released for pid %d\n", pid ? pid : getpid());
    else
        printf("Shadow page released at 0x%lx for pid %d\n", addr, pid ? pid : getpid());
    return 0;
}

/* ===== Self-test support ===== */

/*
 * Test functions for self-test mode.
 * Each is page-aligned so they land on separate pages, avoiding shadow page
 * interference between tests.  noinline prevents the compiler from folding them.
 */
__attribute__((noinline, aligned(4096)))
static long selftest_bp_func(long a, long b) { return a + b; }

__attribute__((noinline, aligned(4096)))
static long selftest_regmod_func(long a, long b) { return a + b; }

__attribute__((noinline, aligned(4096)))
static long selftest_patch_func(void) { return 42; }

/* Test functions for multi-size patch tests (12-byte and 20-byte) */
__attribute__((noinline, aligned(4096)))
static long selftest_patch12_func(long a, long b) { return a + b; }

__attribute__((noinline, aligned(4096)))
static long selftest_patch20_func(long a, long b, long c) { return a + b + c; }

static int run_selftest(void)
{
    int pass = 0, fail = 0;

    printf("===== wxshadow self-test (pid %d) =====\n\n", getpid());

    /* ---- Test 1: Breakpoint transparent execution ---- */
    {
        long (*volatile fn)(long, long) = selftest_bp_func;
        unsigned long addr = (unsigned long)fn;
        int ok = 1;

        printf("[1] Breakpoint: transparent execution\n");
        printf("    func = 0x%lx\n", addr);

        long base = fn(10, 20);
        printf("    baseline:  add(10,20) = %ld\n", base);

        if (prctl(PR_WXSHADOW_SET_BP, 0, addr, 0, 0) < 0) {
            printf("    FAIL SET_BP: %s\n", strerror(errno));
            ok = 0;
        }

        if (ok) {
            long r1 = fn(10, 20);
            printf("    with BP:   add(10,20) = %ld  (expect 30)\n", r1);
            if (r1 != 30) ok = 0;

            long r2 = fn(3, 7);
            printf("    repeat:    add(3,7)   = %ld  (expect 10)\n", r2);
            if (r2 != 10) ok = 0;

            prctl(PR_WXSHADOW_DEL_BP, 0, addr, 0, 0);

            long r3 = fn(10, 20);
            printf("    after del: add(10,20) = %ld  (expect 30)\n", r3);
            if (r3 != 30) ok = 0;
        }

        printf("    >> %s\n\n", ok ? "PASS" : "FAIL");
        if (ok) pass++; else fail++;
    }

    /* ---- Test 2: Breakpoint + register modification ---- */
    {
        long (*volatile fn)(long, long) = selftest_regmod_func;
        unsigned long addr = (unsigned long)fn;
        int ok = 1;

        printf("[2] Breakpoint: register modification (x0)\n");
        printf("    func = 0x%lx\n", addr);

        if (prctl(PR_WXSHADOW_SET_BP, 0, addr, 0, 0) < 0) {
            printf("    FAIL SET_BP: %s\n", strerror(errno));
            ok = 0;
        }
        if (ok && prctl(PR_WXSHADOW_SET_REG, 0, addr, 0 /*x0*/, 99) < 0) {
            printf("    FAIL SET_REG: %s\n", strerror(errno));
            prctl(PR_WXSHADOW_DEL_BP, 0, addr, 0, 0);
            ok = 0;
        }

        if (ok) {
            /* x0 changed 10 -> 99, so result = 99 + 20 = 119 */
            long r = fn(10, 20);
            printf("    add(10,20) with x0=99: %ld  (expect 119)\n", r);
            if (r != 119) ok = 0;

            prctl(PR_WXSHADOW_DEL_BP, 0, addr, 0, 0);
        }

        printf("    >> %s\n\n", ok ? "PASS" : "FAIL");
        if (ok) pass++; else fail++;
    }

    /* ---- Test 3: Patch shadow page + release ---- */
    {
        long (*volatile fn)(void) = selftest_patch_func;
        unsigned long addr = (unsigned long)fn;
        int ok = 1;

        /* AArch64: mov x0, #0 ; ret */
        unsigned char patch[] = {
            0x00, 0x00, 0x80, 0xd2,   /* mov x0, #0 */
            0xc0, 0x03, 0x5f, 0xd6    /* ret         */
        };

        printf("[3] Patch: replace function body + release\n");
        printf("    func = 0x%lx\n", addr);

        long base = fn();
        printf("    baseline:  get42() = %ld\n", base);

        if (prctl(PR_WXSHADOW_PATCH, 0, addr,
                  (unsigned long)patch, sizeof(patch)) < 0) {
            printf("    FAIL PATCH: %s\n", strerror(errno));
            ok = 0;
        }

        if (ok) {
            long r1 = fn();
            printf("    patched:   get42() = %ld  (expect 0)\n", r1);
            if (r1 != 0) ok = 0;

            if (prctl(PR_WXSHADOW_RELEASE, 0, addr, 0, 0) < 0) {
                printf("    FAIL RELEASE: %s\n", strerror(errno));
                ok = 0;
            }
        }

        if (ok) {
            long r2 = fn();
            printf("    released:  get42() = %ld  (expect 42)\n", r2);
            if (r2 != 42) ok = 0;
        }

        printf("    >> %s\n\n", ok ? "PASS" : "FAIL");
        if (ok) pass++; else fail++;
    }

    /* ---- Test 4: Patch 12 bytes (3 instructions) ---- */
    {
        long (*volatile fn)(long, long) = selftest_patch12_func;
        unsigned long addr = (unsigned long)fn;
        int ok = 1;

        /* AArch64: mov x0, #1001 ; nop ; ret  (12 bytes) */
        unsigned char patch[] = {
            0x20, 0x7d, 0x80, 0xd2,   /* mov x0, #0x3e9 (1001) */
            0x1f, 0x20, 0x03, 0xd5,   /* nop                    */
            0xc0, 0x03, 0x5f, 0xd6    /* ret                    */
        };

        printf("[4] Patch 12 bytes: 3-instruction replacement\n");
        printf("    func = 0x%lx\n", addr);

        long base = fn(10, 20);
        printf("    baseline:  add(10,20) = %ld\n", base);

        if (prctl(PR_WXSHADOW_PATCH, 0, addr,
                  (unsigned long)patch, sizeof(patch)) < 0) {
            printf("    FAIL PATCH: %s\n", strerror(errno));
            ok = 0;
        }

        if (ok) {
            long r1 = fn(10, 20);
            printf("    patched:   add(10,20) = %ld  (expect 1001)\n", r1);
            if (r1 != 1001) ok = 0;
        }

        if (ok) {
            if (prctl(PR_WXSHADOW_RELEASE, 0, addr, 0, 0) < 0) {
                printf("    FAIL RELEASE: %s\n", strerror(errno));
                ok = 0;
            }
        }

        if (ok) {
            long r2 = fn(10, 20);
            printf("    released:  add(10,20) = %ld  (expect 30)\n", r2);
            if (r2 != 30) ok = 0;
        }

        printf("    >> %s\n\n", ok ? "PASS" : "FAIL");
        if (ok) pass++; else fail++;
    }

    /* ---- Test 5: Patch 20 bytes (5 instructions) ---- */
    {
        long (*volatile fn)(long, long, long) = selftest_patch20_func;
        unsigned long addr = (unsigned long)fn;
        int ok = 1;

        /* AArch64: mov x0, #0x29a (666) ; nop ; nop ; nop ; ret  (20 bytes) */
        unsigned char patch[] = {
            0x40, 0x53, 0x80, 0xd2,   /* mov x0, #0x29a (666) */
            0x1f, 0x20, 0x03, 0xd5,   /* nop                  */
            0x1f, 0x20, 0x03, 0xd5,   /* nop                  */
            0x1f, 0x20, 0x03, 0xd5,   /* nop                  */
            0xc0, 0x03, 0x5f, 0xd6    /* ret                  */
        };

        printf("[5] Patch 20 bytes: 5-instruction replacement\n");
        printf("    func = 0x%lx\n", addr);

        long base = fn(1, 2, 3);
        printf("    baseline:  add3(1,2,3) = %ld\n", base);

        if (prctl(PR_WXSHADOW_PATCH, 0, addr,
                  (unsigned long)patch, sizeof(patch)) < 0) {
            printf("    FAIL PATCH: %s\n", strerror(errno));
            ok = 0;
        }

        if (ok) {
            long r1 = fn(1, 2, 3);
            printf("    patched:   add3(1,2,3) = %ld  (expect 666)\n", r1);
            if (r1 != 666) ok = 0;
        }

        if (ok) {
            if (prctl(PR_WXSHADOW_RELEASE, 0, addr, 0, 0) < 0) {
                printf("    FAIL RELEASE: %s\n", strerror(errno));
                ok = 0;
            }
        }

        if (ok) {
            long r2 = fn(1, 2, 3);
            printf("    released:  add3(1,2,3) = %ld  (expect 6)\n", r2);
            if (r2 != 6) ok = 0;
        }

        printf("    >> %s\n\n", ok ? "PASS" : "FAIL");
        if (ok) pass++; else fail++;
    }

    int total = pass + fail;
    printf("===== Results: %d/%d passed =====\n", pass, total);
    return fail > 0 ? 1 : 0;
}

int main(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"pid",     required_argument, 0, 'p'},
        {"addr",    required_argument, 0, 'a'},
        {"base",    required_argument, 0, 'b'},
        {"offset",  required_argument, 0, 'o'},
        {"reg",     required_argument, 0, 'r'},
        {"delete",  no_argument,       0, 'd'},
        {"maps",    no_argument,       0, 'm'},
        {"patch",   required_argument, 0, 'P'},
        {"release", no_argument,       0, 'L'},
        {"selftest",no_argument,       0, 't'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    pid_t pid = 0;
    unsigned long addr = 0;
    unsigned long offset = 0;
    char *lib_name = NULL;
    int do_delete = 0;
    int do_maps = 0;
    char *patch_hex = NULL;
    int do_release = 0;
    int do_selftest = 0;
    struct reg_mod reg_mods[MAX_REG_MODS];
    int nr_reg_mods = 0;

    int opt;
    int option_index = 0;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    while ((opt = getopt_long(argc, argv, "p:a:b:o:r:dmth",
                              long_options, &option_index)) != -1) {
        switch (opt) {
        case 'p':
            pid = atoi(optarg);
            break;
        case 'a':
            addr = strtoull(optarg, NULL, 0);
            break;
        case 'b':
            lib_name = optarg;
            break;
        case 'o':
            offset = strtoull(optarg, NULL, 0);
            break;
        case 'r':
            if (nr_reg_mods >= MAX_REG_MODS) {
                fprintf(stderr, "Too many register modifications (max %d)\n",
                        MAX_REG_MODS);
                return 1;
            }
            if (parse_reg_mod(optarg, &reg_mods[nr_reg_mods]) < 0) {
                fprintf(stderr, "Invalid register modification: %s\n", optarg);
                fprintf(stderr, "Format: x0=value or sp=value\n");
                return 1;
            }
            nr_reg_mods++;
            break;
        case 'd':
            do_delete = 1;
            break;
        case 'm':
            do_maps = 1;
            break;
        case 'P':
            patch_hex = optarg;
            break;
        case 'L':
            do_release = 1;
            break;
        case 't':
            do_selftest = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Self-test mode */
    if (do_selftest)
        return run_selftest();

    /* Show maps mode */
    if (do_maps) {
        show_maps(pid);
        return 0;
    }

    /* Calculate address from lib+offset if specified */
    if (lib_name) {
        unsigned long base = find_lib_base(pid, lib_name);
        if (base == 0) {
            fprintf(stderr, "Library '%s' not found in pid %d maps\n",
                    lib_name, pid ? pid : getpid());
            return 1;
        }
        addr = base + offset;
        printf("Found %s at base 0x%lx, target addr = 0x%lx\n",
               lib_name, base, addr);
    }

    /* Release mode (addr=0 means release all) */
    if (do_release) {
        return release_shadow(pid, addr) < 0 ? 1 : 0;
    }

    /* Delete mode (addr=0 means delete all) */
    if (do_delete) {
        return del_breakpoint(pid, addr) < 0 ? 1 : 0;
    }

    if (addr == 0 && !do_maps) {
        fprintf(stderr, "No address specified. Use -a <addr> or -b <lib> -o <offset>\n");
        return 1;
    }

    /* Patch mode */
    if (patch_hex) {
        unsigned char patch_buf[4096];
        int patch_len = parse_hex_string(patch_hex, patch_buf, sizeof(patch_buf));
        if (patch_len < 0)
            return 1;
        return patch_shadow(pid, addr, patch_buf, patch_len) < 0 ? 1 : 0;
    }

    /* Set breakpoint */
    if (set_breakpoint(pid, addr) < 0)
        return 1;

    /* Set register modifications */
    for (int i = 0; i < nr_reg_mods; i++) {
        if (set_reg_mod(pid, addr, reg_mods[i].reg_idx, reg_mods[i].value) < 0)
            return 1;
    }

    return 0;
}
