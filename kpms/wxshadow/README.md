# wxshadow

W^X Shadow Memory — 基于 KernelPatch 的用户态代码隐藏断点/Patch 模块 (ARM64)。

通过 shadow page 技术在用户进程代码段设置隐藏断点或自定义 patch：进程读取时看到原始代码，执行时触发修改后的指令。

## 原理

- **Shadow 页**: 复制原始代码页，在断点处写入 BRK 指令（或自定义 patch），设置 `--x` 权限
- **隐藏效果**: 进程读取时切换到 `r--` 原始页，执行时触发 shadow 页内容
- **单步恢复**: BRK 触发后切换到 `r-x` 原始页执行原始指令，完成后切回 shadow

**页面状态机:**

```
NONE → SHADOW_X(--x) ↔ ORIGINAL(r--) ↔ STEPPING(r-x)
                    ↘ DORMANT (hook 退休，保留 shadow)
```

## 编译

```bash
mkdir build && cd build
cmake -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc ..
make wxshadow.kpm       # KPM 模块
make wxshadow_client    # 用户态客户端
```

## 文件结构

| 文件 | 说明 |
|------|------|
| `wxshadow.h` | 数据结构、prctl 常量、PTE 定义 |
| `wxshadow.c` | 核心实现：页面生命周期、refcount、全局状态 |
| `wxshadow_handlers.c` | BRK/单步/页面 fault/fork/exit_mmap/GUP 处理 |
| `wxshadow_bp.c` | 断点/patch/release 操作、prctl 分发 |
| `wxshadow_pgtable.c` | 页表操作、PTE 切换、TLB flush |
| `wxshadow_scan.c` | 偏移量扫描、符号解析 |
| `wxshadow_internal.h` | 内部接口、内联函数、内核函数指针 |
| `wxshadow_client.c` | 用户态客户端工具 |

## prctl 接口

通过 hook `prctl` 系统调用提供用户态接口：

| 命令 | 值 | 说明 |
|------|------|------|
| `PR_WXSHADOW_SET_BP` | `0x57580001` | 设置隐藏断点 |
| `PR_WXSHADOW_SET_REG` | `0x57580002` | 配置断点触发时的寄存器修改 |
| `PR_WXSHADOW_DEL_BP` | `0x57580003` | 删除断点 |
| `PR_WXSHADOW_SET_TLB_MODE` | `0x57580004` | 设置 TLB flush 模式 |
| `PR_WXSHADOW_GET_TLB_MODE` | `0x57580005` | 获取当前 TLB flush 模式 |
| `PR_WXSHADOW_PATCH` | `0x57580006` | 自定义 patch（copy_from_user 写入 shadow） |
| `PR_WXSHADOW_RELEASE` | `0x57580008` | 释放 shadow，恢复原始页 |

## 客户端用法

```bash
# 查看目标进程可执行区域
./wxshadow_client -p <pid> -m

# 设置断点（按地址）
./wxshadow_client -p <pid> -a 0x7b5c001234

# 设置断点（按库名 + 偏移）
./wxshadow_client -p <pid> -b libc.so -o 0x12345

# 设置断点并修改寄存器
./wxshadow_client -p <pid> -a 0x7b5c001234 -r x0=0 -r x1=0x100

# 删除指定断点
./wxshadow_client -p <pid> -a 0x7b5c001234 -d

# 删除所有断点
./wxshadow_client -p <pid> -d

# 自定义 patch（NOP）
./wxshadow_client -p <pid> -a 0x7b5c001234 --patch d503201f

# 自定义 patch（mov x0, #0; ret）
./wxshadow_client -p <pid> -a 0x7b5c001234 --patch 000080d2c0035fd6

# 释放指定地址的 shadow
./wxshadow_client -p <pid> -a 0x7b5c001234 --release

# 释放所有 shadow
./wxshadow_client -p <pid> --release
```

## 部署

```bash
adb push build/kpms/wxshadow/wxshadow.kpm /data/local/tmp/
adb push build/kpms/wxshadow/wxshadow_client /data/local/tmp/
adb shell chmod +x /data/local/tmp/wxshadow_client

# 加载模块（需要 KernelPatch superkey）
kpatch <superkey> kpm load /data/local/tmp/wxshadow.kpm

# 查看日志
dmesg | grep wxshadow

# 卸载模块
kpatch <superkey> kpm unload wxshadow
```

## 关键限制

- 仅支持 ARM64
- PATCH 接口不能跨页（offset + len <= PAGE_SIZE）
- 每页最多 128 个断点、128 个 patch
- 每个断点最多 4 个寄存器修改
- 需要 KernelPatch 框架支持

## Hook 点

| Hook 目标 | 方式 | 用途 |
|-----------|------|------|
| `prctl` | syscall hook | 用户态接口 |
| `brk_handler` | direct hook | BRK 断点处理 |
| `single_step_handler` | direct hook | 单步执行处理 |
| `do_page_fault` | hook (可选) | 读取隐藏 |
| `follow_page_pte` | hook (可选) | GUP 隐藏 |
| `copy_process` | hook | fork 保护 |
| `exit_mmap` | hook | 进程退出清理 |

