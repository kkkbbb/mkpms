# wxshadow

## Build

```bash
cmake --build build --target wxshadow.kpm wxshadow_client -j4
```

## Device Race Regression

仓库内提供了两层脚本：

- `scripts/wxshadow_race.sh`
  设备侧 worker。负责并发执行 `patch/release`、`bp/release`、`release_all`，并同时触发点按和 `memread`。
- `scripts/run_device_race_regression.sh`
  主机侧 wrapper。负责构建产物、推送到 `adb` 设备、加载 `wxshadow`、解析三方进程地址并跑竞态回归。

默认回归对象是 `com.example.crcdemo` / `libcrcdemo.so`，会自动解析：

- `get_secret_value`
- `calculate_crc32`
- `get_secret_value` 内首条 `ret`

如果 APK 导出的是 C++ mangled 符号，wrapper 会自动回退到：

- `_Z16get_secret_valuei`
- `_Z15calculate_crc32PKhm`

### 依赖

- `adb`
- `cmake`
- `unzip`
- `aarch64-linux-gnu-gcc`
- `readelf`
- `aarch64-linux-gnu-objdump`
- 设备已 root，且允许执行 `su -c`

### 用法

```bash
kpms/wxshadow/scripts/run_device_race_regression.sh --superkey wwb12345
```

常用可选项：

```bash
kpms/wxshadow/scripts/run_device_race_regression.sh \
  --superkey wwb12345 \
  --serial 10.0.0.205:5555 \
  --package com.example.crcdemo \
  --lib libcrcdemo.so \
  --patch-loops 120 \
  --bp-loops 120 \
  --release-all-loops 80
```

如果目标 app 已经启动，可以加：

```bash
kpms/wxshadow/scripts/run_device_race_regression.sh --superkey wwb12345 --no-start-app
```

默认行为：

- 推送 `wxshadow.kpm`、`wxshadow_client`
- 如本地缺失，会构建并推送 `tools/kpatch/kpatch.c` 和 `tools/memread.c` 对应的 arm64 静态二进制
- 顺序执行 `patch_release`、`bp_release`、`release_all`
- 检查 app PID 是否重启
- 检查本轮新增内核日志里是否出现这些已知坏信号：
  - `step handler: NOT FOUND`
  - `BRK: not our breakpoint`
  - `Bad page map`
  - `Bad page state`
  - `BUG: Bad rss-counter`
- 脚本退出时默认卸载 `wxshadow`

需要保留模块时可加 `--keep-loaded`。
