# WXSHADOW Changelog

## [1.1.0] - 2026-01-14

### Added - 新增自定义 Hook 接口

新增三个高级接口，允许用户自定义 hook 代码，而不是使用固定的 BRK 指令：

#### 1. READ 接口 (`PR_WXSHADOW_READ = 0x57580006`)
- 创建 shadow page 并复制原始内容
- 设置权限为 `rw-` (可读写，不可执行)
- 允许用户态程序通过 `/proc/pid/mem` 等方式写入自定义 hook 代码

#### 2. ACTIVE 接口 (`PR_WXSHADOW_ACTIVE = 0x57580007`)
- 将 shadow page 权限从 `rw-` 切换到 `--x` (只可执行)
- 刷新指令缓存，激活 hook
- 实现 hook 隐藏效果

#### 3. RELEASE 接口 (`PR_WXSHADOW_RELEASE = 0x57580008`)
- 恢复原始页面映射 (`r-x`)
- 释放 shadow page 内存
- 清理页面结构

### Changed - 修改

#### 页面状态
- 新增 `WX_STATE_SHADOW_RW` 状态，表示 shadow page 处于可写状态

#### 客户端
- 新增 `--read` 选项：准备 shadow page (rw-)
- 新增 `--active` 选项：激活 shadow page (--x)
- 新增 `--release` 选项：释放 shadow page

### Technical Details - 技术细节

#### 权限管理
- `rw-`: `PTE_USER | PTE_UXN` (可读写，不可执行)
- `--x`: `prot=0` (只可执行)
- `r-x`: `PTE_USER | PTE_RDONLY` (可读可执行)

#### 状态检查
- ACTIVE 只能在 `WX_STATE_SHADOW_RW` 状态下调用
- 自动处理 TLB 和指令缓存刷新

#### 内存管理
- 使用与 SET_BP 相同的页面分配和释放机制
- 支持页面复用（如果 page 已存在，直接切换权限）

### Usage - 使用方法

```bash
# 1. 准备 shadow page (rw-)
./wxshadow_client -p <pid> -a 0x7b5c001234 --read

# 2. 写入自定义 hook 代码 (通过 /proc/pid/mem 或其他方式)

# 3. 激活 shadow (--x)
./wxshadow_client -p <pid> -a 0x7b5c001234 --active

# 4. 释放 shadow
./wxshadow_client -p <pid> -a 0x7b5c001234 --release
```

### Files Modified - 修改的文件

- `wxshadow.h` - 添加新的 prctl 常量和状态
- `wxshadow_bp.c` - 实现三个新函数和 prctl 处理逻辑
- `wxshadow_internal.h` - 添加函数声明
- `wxshadow.c` - 更新初始化日志信息
- `wxshadow_client.c` - 添加客户端支持
- `CLAUDE.md` - 更新文档

### Documentation - 文档

- 新增 `README_NEW_INTERFACES.md` - 详细使用说明
- 更新 `CLAUDE.md` - 添加新接口说明

---

## [1.0.0] - Initial Release

### Features
- BRK 断点隐藏机制
- Shadow page 技术
- 寄存器修改支持
- 读取隐藏 (read fault handling)
- 单步执行支持
- 无锁页表操作
- TLB flush 多种方案支持
