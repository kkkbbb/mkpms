/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpatch - minimal KernelPatch userspace CLI
 *
 * Usage:
 *   kpatch <superkey> hello
 *   kpatch <superkey> kpm load <path> [args]
 *   kpatch <superkey> kpm unload <name>
 *   kpatch <superkey> kpm list
 *   kpatch <superkey> kpm num
 *   kpatch <superkey> kpm info <name>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>

/* ---- KernelPatch ABI ---- */

#define KP_MAJOR 0
#define KP_MINOR 12
#define KP_PATCH 3

#define __NR_supercall      45

#define SUPERCALL_HELLO     0x1000
#define SUPERCALL_HELLO_MAGIC 0x11581158
#define SUPERCALL_HELLO_ECHO  "hello1158"

#define SUPERCALL_KERNELPATCH_VER 0x1008
#define SUPERCALL_KERNEL_VER      0x1009

#define SUPERCALL_KPM_LOAD    0x1020
#define SUPERCALL_KPM_UNLOAD  0x1021
#define SUPERCALL_KPM_CONTROL 0x1022
#define SUPERCALL_KPM_NUMS    0x1030
#define SUPERCALL_KPM_LIST    0x1031
#define SUPERCALL_KPM_INFO    0x1032

#define SUPERCALL_KEY_MAX_LEN 0x40

static long ver_and_cmd(long cmd)
{
    uint32_t ver = (KP_MAJOR << 16) | (KP_MINOR << 8) | KP_PATCH;
    return ((long)ver << 32) | (0x1158 << 16) | (cmd & 0xFFFF);
}

/* ---- supercall wrappers ---- */

static long sc_hello(const char *key)
{
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_HELLO));
}

static uint32_t sc_kp_ver(const char *key)
{
    return (uint32_t)syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KERNELPATCH_VER));
}

static uint32_t sc_k_ver(const char *key)
{
    return (uint32_t)syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KERNEL_VER));
}

static long sc_kpm_load(const char *key, const char *path, const char *args)
{
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KPM_LOAD), path, args, (void *)0);
}

static long sc_kpm_unload(const char *key, const char *name)
{
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KPM_UNLOAD), name, (void *)0);
}

static long sc_kpm_nums(const char *key)
{
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KPM_NUMS));
}

static long sc_kpm_list(const char *key, char *buf, int len)
{
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KPM_LIST), buf, len);
}

static long sc_kpm_info(const char *key, const char *name, char *buf, int len)
{
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KPM_INFO), name, buf, len);
}

/* ---- commands ---- */

static void cmd_hello(const char *key)
{
    long ret = sc_hello(key);
    if (ret == SUPERCALL_HELLO_MAGIC) {
        printf("%s\n", SUPERCALL_HELLO_ECHO);
        uint32_t kpv = sc_kp_ver(key);
        uint32_t kv  = sc_k_ver(key);
        printf("KernelPatch: %d.%d.%d\n",
               (kpv >> 16) & 0xff, (kpv >> 8) & 0xff, kpv & 0xff);
        printf("Kernel:      %d.%d.%d\n",
               (kv >> 16) & 0xff, (kv >> 8) & 0xff, kv & 0xff);
    } else {
        fprintf(stderr, "KernelPatch not ready (ret=%ld errno=%d)\n", ret, errno);
        exit(1);
    }
}

static void cmd_kpm_load(const char *key, const char *path, const char *args)
{
    long ret = sc_kpm_load(key, path, args);
    if (ret == 0)
        printf("loaded: %s\n", path);
    else
        fprintf(stderr, "load failed: %ld (errno=%d)\n", ret, errno);
    exit(ret != 0);
}

static void cmd_kpm_unload(const char *key, const char *name)
{
    long ret = sc_kpm_unload(key, name);
    if (ret == 0)
        printf("unloaded: %s\n", name);
    else
        fprintf(stderr, "unload failed: %ld (errno=%d)\n", ret, errno);
    exit(ret != 0);
}

static void cmd_kpm_num(const char *key)
{
    long n = sc_kpm_nums(key);
    printf("%ld\n", n);
}

static void cmd_kpm_list(const char *key)
{
    char buf[4096] = { 0 };
    long ret = sc_kpm_list(key, buf, sizeof(buf) - 1);
    if (ret > 0)
        printf("%s", buf);
    else if (ret == 0)
        printf("(no modules loaded)\n");
    else
        fprintf(stderr, "list failed: %ld (errno=%d)\n", ret, errno);
}

static void cmd_kpm_info(const char *key, const char *name)
{
    char buf[4096] = { 0 };
    long ret = sc_kpm_info(key, name, buf, sizeof(buf) - 1);
    if (ret > 0)
        printf("%s", buf);
    else
        fprintf(stderr, "info failed: %ld (errno=%d)\n", ret, errno);
}

/* ---- usage ---- */

static void usage_kpm(const char *prog)
{
    fprintf(stderr,
        "Usage: %s <key> kpm <subcommand> [args]\n"
        "\n"
        "Subcommands:\n"
        "  load <path> [args]   Load a KPM module\n"
        "  unload <name>        Unload a KPM module by name\n"
        "  list                 List loaded modules\n"
        "  num                  Print number of loaded modules\n"
        "  info <name>          Print module info\n",
        prog);
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s <superkey> <command> [args]\n"
        "\n"
        "Commands:\n"
        "  hello                Check KP is running, print versions\n"
        "  kpm ...              KPM module management\n",
        prog);
}

/* ---- main ---- */

int main(int argc, char **argv)
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    const char *key = argv[1];
    const char *cmd = argv[2];

    if (strlen(key) >= SUPERCALL_KEY_MAX_LEN) {
        fprintf(stderr, "superkey too long\n");
        return 1;
    }

    if (strcmp(cmd, "hello") == 0) {
        cmd_hello(key);
        return 0;
    }

    if (strcmp(cmd, "kpm") == 0) {
        if (argc < 4) {
            usage_kpm(argv[0]);
            return 1;
        }
        const char *sub = argv[3];

        if (strcmp(sub, "load") == 0) {
            if (argc < 5) {
                fprintf(stderr, "Usage: %s <key> kpm load <path> [args]\n", argv[0]);
                return 1;
            }
            const char *path = argv[4];
            const char *args = argc >= 6 ? argv[5] : NULL;
            cmd_kpm_load(key, path, args);
            return 0;
        }
        if (strcmp(sub, "unload") == 0) {
            if (argc < 5) {
                fprintf(stderr, "Usage: %s <key> kpm unload <name>\n", argv[0]);
                return 1;
            }
            cmd_kpm_unload(key, argv[4]);
            return 0;
        }
        if (strcmp(sub, "list") == 0) {
            cmd_kpm_list(key);
            return 0;
        }
        if (strcmp(sub, "num") == 0) {
            cmd_kpm_num(key);
            return 0;
        }
        if (strcmp(sub, "info") == 0) {
            if (argc < 5) {
                fprintf(stderr, "Usage: %s <key> kpm info <name>\n", argv[0]);
                return 1;
            }
            cmd_kpm_info(key, argv[4]);
            return 0;
        }
        usage_kpm(argv[0]);
        return 1;
    }

    usage(argv[0]);
    return 1;
}
