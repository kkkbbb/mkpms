/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>
#include <hook.h>
#include "../common/kpm_demo_helpers.h"

///< The name of the module, each KPM must has a unique name.
KPM_MODULE_INFO("kpm-hide-maps", "1.0.0", "GPL v2", "wwb", "KernelPatch Module Example");


typedef struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
} seq_file;

void *(*vmalloc)(unsigned long size);
void (*vfree)(void * ponit);
void *show_map_vma;
int flag = false;

void show_map_vma_before(hook_fargs2_t* args, void * udata){
    seq_file* m = (seq_file*) args->arg0;
    args->local.data0 = m->count;
}

void show_map_vma_after(hook_fargs2_t* args, void * udata){
    // pr_info("KP: enter vma after \n");

    int start = args->local.data0;
    seq_file* m = (seq_file*) args->arg0;
    int end = m->count;
    // 检测maps是否符合我们的情况
    char * line = vmalloc(end - start + 1);
    // for (int i = 0; i < end - start; i++){
    //     line[i] = m->buf[start + i];
    // }
    memcpy(line, m->buf + start, end - start);
    line[end - start] = 0;

    char *pos = strstr(m->buf + start, "rwxp");
    char *pos1 = strstr(m->buf + start, "wwb_so");
    if ((pos && pos < m->buf + end) || (pos1 && pos1 < m->buf + end)) {
        // pos[1] = '-';  // rwxp -> r-xp
        m->count = start;
    }
    vfree(line);
}

/**
 * @brief hello world initialization
 * @details 
 * 
 * @param args 
 * @param reserved 
 * @return int 
 */
static long hello_init(const char *args, const char *event, void *__user reserved)
{
    (void)reserved;
    kpm_demo_log_init("kpm hello", event, args);

    vmalloc = (void *)kallsyms_lookup_name("vmalloc");
    vfree = (void *)kallsyms_lookup_name("vfree");
    pr_info("vmalloc: %p, vfree: %p\n", vmalloc, vfree);

    show_map_vma = (void *)kallsyms_lookup_name("show_map_vma");
    if (show_map_vma) {
        hook_wrap2(show_map_vma, show_map_vma_before, show_map_vma_after, NULL);
        pr_info("test_hide show_map_vma sucess %p", show_map_vma);
    } else {
        pr_info("test_hide show_map_vma fail");
    }
    return 0;
}



static long hello_control0(const char *args, char *__user out_msg, int outlen)
{
    return kpm_demo_echo_control("kpm hello", args, out_msg, outlen);
}



static long hello_exit(void *__user reserved)
{
    (void)reserved;
    unhook(show_map_vma);
    return kpm_demo_log_exit("kpm hello");
}

KPM_INIT(hello_init);
KPM_CTL0(hello_control0);
KPM_EXIT(hello_exit);
