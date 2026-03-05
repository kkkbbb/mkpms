/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * anti-detect: Block apps from accessing qemu/goldfish files
 * Shell (uid 2000) and root (uid 0) are exempted.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>
#include <uapi/asm-generic/errno.h>

KPM_NAME("anti-detect");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("wwb");
KPM_DESCRIPTION("Block app access to qemu/goldfish files");

#define SHELL_UID 2000
#define ROOT_UID  0
#define FILENAME_BUF_SIZE 256

#ifndef __NR_faccessat2
#define __NR_faccessat2 439
#endif

static int should_block(const char *filename)
{
    return strstr(filename, "goldfish") || strstr(filename, "qemu");
}

static void before_file_syscall(hook_fargs4_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (uid == ROOT_UID || uid == SHELL_UID) return;

    const char __user *ufilename = (const char __user *)syscall_argn(args, 1);
    char buf[FILENAME_BUF_SIZE];
    long len = compat_strncpy_from_user(buf, ufilename, sizeof(buf));
    if (len <= 0) return;

    if (should_block(buf)) {
        args->ret = -ENOENT;
        args->skip_origin = 1;
    }
}

struct syscall_hook_entry {
    int nr;
    int narg;
};

static const struct syscall_hook_entry hooks[] = {
    { __NR_openat,        4 },
    { __NR_faccessat,     3 },
    { __NR_faccessat2,    4 },
    { __NR3264_fstatat,   4 },
    { __NR_statx,         5 },
    { __NR_readlinkat,    4 },
};

#define NUM_HOOKS (sizeof(hooks) / sizeof(hooks[0]))

static int hooks_installed;

static long anti_detect_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("anti-detect: loading...\n");

    for (hooks_installed = 0; hooks_installed < NUM_HOOKS; hooks_installed++) {
        hook_err_t err = hook_syscalln(hooks[hooks_installed].nr,
                                       hooks[hooks_installed].narg,
                                       before_file_syscall, 0, 0);
        if (err) {
            pr_err("anti-detect: hook syscall %d failed: %d\n",
                   hooks[hooks_installed].nr, err);
            goto rollback;
        }
    }

    pr_info("anti-detect: all hooks installed\n");
    return 0;

rollback:
    while (hooks_installed-- > 0)
        unhook_syscalln(hooks[hooks_installed].nr, before_file_syscall, 0);
    return -1;
}

static long anti_detect_exit(void *__user reserved)
{
    int i;
    for (i = NUM_HOOKS; i-- > 0;)
        unhook_syscalln(hooks[i].nr, before_file_syscall, 0);
    pr_info("anti-detect: unloaded\n");
    return 0;
}

KPM_INIT(anti_detect_init);
KPM_EXIT(anti_detect_exit);
