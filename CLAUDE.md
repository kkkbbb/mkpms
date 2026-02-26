# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# KernelPatch Modules Project

## 项目概述

KernelPatch (KP) 模块开发项目，用于开发可动态加载的内核模块 (KPM)。
参考内核源码: `~/android-kernel`（仅参考，实际版本可能不一致）

## 目录结构

```
mkpms/
├── kernel/          # KernelPatch 框架代码 (只读参考，不要修改!)
│   ├── base/        # hook, 内存管理等基础功能
│   ├── include/     # 公共头文件
│   ├── patch/       # 补丁和模块加载
│   └── linux/       # Linux 内核头文件适配版本
├── kpms/            # KPM 模块开发目录
│   ├── demo-hello/
│   ├── demo-inlinehook/
│   ├── demo-syscallhook/
│   ├── hide-maps/
│   └── wxshadow/    # W^X Shadow 断点隐藏模块
├── CMakeLists.txt
└── hello.lds
```

## 编译

```bash
mkdir build && cd build
cmake -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc ..
make                    # 所有模块
make wxshadow.kpm       # 单个 KPM
make wxshadow_client    # 用户态客户端
```

## KPM 模块开发

### 模块模板

```c
#include <kpmodule.h>
#include <linux/printk.h>

KPM_NAME("module-name");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("author");
KPM_DESCRIPTION("description");

static long module_init(const char *args, const char *event, void *reserved) {
    return 0;
}
static long module_exit(void *reserved) {
    return 0;
}

KPM_INIT(module_init);
KPM_EXIT(module_exit);
```

### 常用 API

```c
kallsyms_lookup_name(name)               // 查找内核符号
hook_wrap(func, before, after, udata)    // Hook 函数
hook_syscalln(nr, narg, before, after, udata)  // Hook 系统调用
pr_info / pr_err                         // 内核日志
```

### KP 框架提供的 API

**task_struct (`linux/sched.h`, `linux/init_task.h`):**
```c
extern struct task_struct_offset task_struct_offset;  // 框架已检测偏移量
extern struct task_struct *init_task;                 // swapper 进程

const char *get_task_comm(struct task_struct *task);
struct task_struct *find_task_by_vpid(pid_t pid);
struct task_struct *next_task(struct task_struct *task);

// PID/TGID (无需扫描偏移量)
pid_t pid  = task_pid_vnr(task);
pid_t tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, NULL);
```

**框架已检测的 task_struct 偏移量:** `comm_offset`, `cred_offset`, `active_mm_offset`, `stack_offset`
**需自行扫描:** `tasks_offset`, `mm_offset`

**mm_struct (`linux/mm_types.h`):**
```c
extern struct mm_struct_offset mm_struct_offset;
// 可用: pgd_offset, mmap_base_offset, task_size_offset, start_code_offset 等
```

**Spinlock (`linux/spinlock.h`):**
```c
DEFINE_SPINLOCK(my_lock);
spin_lock(&my_lock);  spin_unlock(&my_lock);
spin_lock_irqsave(&my_lock, flags);  spin_unlock_irqrestore(&my_lock, flags);
```

**链表 (`linux/list.h`):**
```c
LIST_HEAD(my_list);
list_add / list_add_tail / list_del_init / list_empty
list_for_each(pos, head) / list_for_each_safe(pos, n, head)
container_of(ptr, type, member)
// 注意: list_del_init() 而非 list_del()，节点可安全重用
```

**current (`asm/current.h`):**
```c
#include <asm/current.h>
struct task_struct *task = current;  // ARM64: sp_el0 存储 current
```

**is_kva (推荐替代 is_kimg_range):**
```c
// ARM64 内核虚拟地址高 16 位为 0xffff，包括动态分配的 slab/kmalloc
static inline bool is_kva(unsigned long addr) { return (addr >> 48) == 0xffff; }
```

---

## WXSHADOW 模块

### 文件

| 文件 | 说明 |
|------|------|
| `kpms/wxshadow/wxshadow.h` | 数据结构定义 |
| `kpms/wxshadow/wxshadow.c` | 核心实现 |
| `kpms/wxshadow/wxshadow_bp.c` | 断点管理 |
| `kpms/wxshadow/wxshadow_pgtable.c` | 页表操作 |
| `kpms/wxshadow/wxshadow_scan.c` | 偏移量扫描 |
| `kpms/wxshadow/wxshadow_internal.h` | 内部接口 |
| `kpms/wxshadow/wxshadow_client.c` | 用户态客户端 |

### 架构概述

通过 shadow 页面技术在用户进程代码段设置隐藏断点：
- **Shadow 页**: 复制原始代码页，在断点处写入 BRK 指令，设置 `--x` 权限
- **隐藏效果**: 进程读取时看到原始代码（切换到 `r--` 原始页），执行时触发 BRK
- **单步恢复**: BRK 触发后切换到 `r-x` 原始页执行原始指令，完成后切回 shadow

**页面状态:** `NONE → SHADOW_X(--x) ↔ ORIGINAL(r--) ↔ STEPPING(r-x)`

**实现方式:**
- 用户接口: Hook `prctl` 系统调用
- BRK 处理: 直接 hook `brk_handler`
- 单步执行: 直接 hook `single_step_handler`
- 页面 fault: Hook `do_page_fault` (可选，用于读取隐藏)
- 无锁页表操作: `global_lock` 只保护链表和状态，页表操作在锁外进行

### 关键常量

```c
WXSHADOW_BRK_IMM         0x007       // BRK 立即数
WXSHADOW_BRK_INSN        0xd42000e0  // BRK #0x7 指令
WXSHADOW_MAX_BPS_PER_PAGE  16        // 每页最大断点数
WXSHADOW_MAX_REG_MODS      4         // 每断点最大寄存器修改数
```

### PTE 权限

| 状态 | 权限 | 说明 |
|------|------|------|
| SHADOW_X | `prot=0` (--x) | 执行触发 BRK，读取触发 fault |
| ORIGINAL | `PTE_USER\|PTE_RDONLY\|PTE_UXN` (r--) | 读取原始内容，执行触发 fault |
| STEPPING | `PTE_USER\|PTE_RDONLY` (r-x) | 单步执行原始指令 |

### prctl 接口

**基础断点:**
```c
#define PR_WXSHADOW_SET_BP   0x57580001
#define PR_WXSHADOW_SET_REG  0x57580002
#define PR_WXSHADOW_DEL_BP   0x57580003

prctl(PR_WXSHADOW_SET_BP,  pid, addr, 0, 0);
prctl(PR_WXSHADOW_SET_REG, pid, addr, reg_idx, value);
prctl(PR_WXSHADOW_DEL_BP,  pid, addr, 0, 0);
```

**自定义 patch:**
```c
#define PR_WXSHADOW_PATCH    0x57580006  // 内核 copy_from_user 写入 shadow VA
#define PR_WXSHADOW_RELEASE  0x57580008  // 释放 shadow，恢复原始页

prctl(PR_WXSHADOW_PATCH,   pid, addr, buf_ptr, len);  // 不能跨页
prctl(PR_WXSHADOW_RELEASE, pid, addr, 0, 0);
```

### kallsyms 解析的符号

| 类别 | 符号 |
|------|------|
| VMA/mm | find_vma, get_task_mm, mmput |
| 页面分配 | __get_free_pages, free_pages |
| 地址转换 | memstart_addr |
| TLB | flush_tlb_page (优先), __flush_tlb_range (备用), TLBI 指令 (fallback) |
| 缓存 | flush_dcache_page, __flush_icache_range |
| 单步 | user_enable_single_step, user_disable_single_step |
| hook 目标 | brk_handler, single_step_handler, do_page_fault |
| RCU | __rcu_read_lock/unlock |
| 内存分配 | kzalloc, kcalloc, kfree |
| 用户内存 | _copy_from_user / copy_from_user / __arch_copy_from_user |

**TLB Flush 优先级:** `flush_tlb_page` → `__flush_tlb_range` → `TLBI VALE1IS` (需要 mm->context.id ASID)

**TLBI 操作数格式:** `{ASID[63:48], VA[47:12]}`

### 偏移量扫描

**mm_context_id_offset**: 在 init 时尝试扫描，失败则延迟到首次 prctl。使用 TTBR0_EL1 ASID 匹配 `mm[0x100..0x400]`。

**tasks_offset / mm_offset**: 在 `wxshadow_scan.c` 的 `detect_task_struct_offsets()` 中动态检测。
- `mm_offset` 优先用 `active_mm_offset - 8`（框架已检测 active_mm）
- 相关变量: `extern int16_t mm_context_id_offset;` (-1 = 未检测)

**VMA 偏移 (静态):**
```c
VMA_VM_START_OFFSET  0x00
VMA_VM_END_OFFSET    0x08
VMA_VM_MM_OFFSET     0x40  // 需动态扫描验证
```

### 客户端使用

```bash
./wxshadow_client -p <pid> -m                              # 查看可执行区域
./wxshadow_client -p <pid> -a 0x7b5c001234                 # 设置断点
./wxshadow_client -p <pid> -b libc.so -o 0x12345           # 库名+偏移
./wxshadow_client -p <pid> -a 0x7b5c001234 -r x0=0 -r x1=0x100  # 修改寄存器
./wxshadow_client -p <pid> -a 0x7b5c001234 -d              # 删除断点
./wxshadow_client -p <pid> -a 0x7b5c001234 --patch d503201f      # NOP patch
./wxshadow_client -p <pid> -a 0x7b5c001234 --patch 000080d2c0035fd6  # mov x0,0; ret
./wxshadow_client -p <pid> -a 0x7b5c001234 --release       # 释放 shadow
```

### 部署

```bash
adb push build/kpms/wxshadow/wxshadow.kpm /data/local/tmp/
adb push build/kpms/wxshadow/wxshadow_client /data/local/tmp/
adb shell chmod +x /data/local/tmp/wxshadow_client
kpatch module load /data/local/tmp/wxshadow.kpm
dmesg | grep wxshadow
```

### 注意事项

- `kernel/` 目录只读参考，不要修改
- VMA/task_struct 偏移量需根据内核版本动态扫描
- PATCH 接口不能跨页 (offset + len <= PAGE_SIZE)
- 卸载时锁内收集 page 指针，锁外执行清理（free_pages 可能阻塞）
- 模块卸载必须 unhook 所有钩子，否则内核崩溃
