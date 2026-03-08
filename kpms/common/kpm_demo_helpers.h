/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef KPM_DEMO_HELPERS_H
#define KPM_DEMO_HELPERS_H

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>

#ifndef KPM_MODULE_INFO
#define KPM_MODULE_INFO(name, version, license, author, description) \
    KPM_NAME(name);                                                  \
    KPM_VERSION(version);                                            \
    KPM_LICENSE(license);                                            \
    KPM_AUTHOR(author);                                              \
    KPM_DESCRIPTION(description)
#endif

static inline long kpm_demo_copy_message(const char *msg, char *__user out_msg,
                                         int outlen)
{
    int len;

    if (!out_msg || outlen <= 0)
        return 0;

    len = strlen(msg ? msg : "");
    if (len < 0)
        return len;

    if (len >= outlen)
        len = outlen - 1;

    return compat_copy_to_user(out_msg, msg ? msg : "", len + 1);
}

static inline long kpm_demo_log_init(const char *name, const char *event,
                                     const char *args)
{
    pr_info("%s init, event: %s, args: %s\n",
            name ? name : "kpm-demo",
            event ? event : "(null)",
            args ? args : "(null)");
    return 0;
}

static inline long kpm_demo_log_exit(const char *name)
{
    pr_info("%s exit\n", name ? name : "kpm-demo");
    return 0;
}

static inline long kpm_demo_echo_control(const char *name, const char *args,
                                         char *__user out_msg, int outlen)
{
    char buf[256];

    snprintf(buf, sizeof(buf), "%s control args: %s",
             name ? name : "kpm-demo",
             args ? args : "");
    pr_info("%s\n", buf);
    return kpm_demo_copy_message(buf, out_msg, outlen);
}

static inline long kpm_demo_log_control(const char *name, const char *args,
                                        char *__user out_msg, int outlen)
{
    pr_info("%s control args: %s\n",
            name ? name : "kpm-demo",
            args ? args : "(null)");
    return kpm_demo_copy_message(args ? args : "", out_msg, outlen);
}

#endif
