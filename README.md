# HMAPlusPlus

HMA++ 是一个面向 Android ARM64 环境的 KernelPatch 模块（KPM）。它通过钩住部分文件系统调用，限制对 `/storage/emulated/0/Android/data/` 下指定包名目录的创建、切换、删除和状态查询操作。

当前源码版本为 `0.0.3`，作者为 `lshwjgpt`。

## 工作方式

模块读取系统调用传入的路径，检查其是否以 `/storage/emulated/0/Android/data/` 开头，再将该前缀后的第一级目录名与内置 `deny_list` 逐项匹配。命中后，跳过原系统调用并返回对应错误；未命中则交由原系统调用处理。

| 操作 | 钩子入口 | 命中后的返回值 |
| --- | --- | --- |
| 创建目录 | `mkdirat` | `-EACCES`（权限不足） |
| 切换工作目录 | `chdir` | `-ENOENT`（路径不存在） |
| 删除目录 | ARM64 下的 `unlinkat`，且带有 `AT_REMOVEDIR` 标志 | `-ENOENT` |
| 查询文件或目录状态 | `newfstatat` 或 `fstatat64`，取决于编译时的系统调用定义 | `-ENOENT` |

匹配范围包括指定包名目录及其子路径。例如，将 `com.example.app` 加入名单后，以下两个路径均可命中上述检查：

```text
/storage/emulated/0/Android/data/com.example.app
/storage/emulated/0/Android/data/com.example.app/files/cache
```

## 配置黑名单

编辑 [HMA++.c](HMA++.c) 中的 `deny_list`，将默认占位项 `ender_you_needs_dir!!!` 替换为需要限制的目录名。通常该目录名就是应用包名：

```c
static const char *deny_list[] = {
    "com.example.app",
    "com.example.another"
};
```

这里填写的是**目标目录对应的包名**，不是调用方应用的包名。当前实现不检查调用方身份，所有经过这些钩子且路径命中的调用都会受到影响，包括目标应用自身的操作。

黑名单编译在模块中，修改后需要重新编译并重新加载模块。当前没有运行时配置文件或动态管理接口。

## 编译

准备以下环境：

- Linux 或 WSL，以及 GNU Make。
- KernelPatch 源码及其 `kernel/` 头文件目录。
- AArch64 交叉编译工具链；现有 Makefile 使用 `aarch64-none-elf-gcc`。

在项目根目录执行，按本机环境替换两个路径：

```bash
make \
  KP_DIR=/path/to/KernelPatch \
  TARGET_COMPILE=/path/to/toolchain/bin/aarch64-none-elf-
```

- `KP_DIR` 指向 KernelPatch 源码根目录，Makefile 默认值为 `../..`。
- `TARGET_COMPILE` 是工具链前缀，需要保留末尾的 `-`。Makefile 中写有作者本机的绝对路径，因此应通过命令行参数覆盖。

编译成功后，项目根目录会生成 `HMA++.kpm`。

清理构建产物：

```bash
make clean
```

## 加载与检查

1. 确认目标 ARM64 设备具备可加载 KPM 的 KernelPatch 环境。
2. 将编译得到的 `HMA++.kpm` 复制到设备，通过所用环境提供的 KPM 管理入口加载。
3. 检查内核日志中以 `[HMA++]` 开头的信息，确认初始化结果；出现 `Failed to hook ...` 时，需要排查对应钩子的加载问题。
4. 使用黑名单中目录的完整绝对路径检查对应操作，并与未加入黑名单的目录进行对照。

具备内核日志读取权限时，可通过以下命令筛选日志：

```bash
dmesg | grep -F '[HMA++]'
```

卸载时使用同一环境提供的 KPM 卸载入口。模块的退出函数会解除已注册的钩子。

## 功能边界

- 当前仅按传入的路径字符串匹配固定前缀，不做路径规范化。相对路径、`/sdcard/Android/data/` 等别名路径，以及其他用户的存储路径不在该前缀的直接匹配范围内。
- 当前仅覆盖上述系统调用，没有实现目录枚举过滤，也没有覆盖 `openat`、`statx` 等其他访问方式。因此不能据此保证目录完全不可见或不可访问。
- 模块不会主动删除、迁移或修改已有目录内容；但拦截创建和访问操作可能影响相关应用的正常运行。
- 仓库未提供经过验证的 Android、内核或 KernelPatch 版本兼容列表，实际效果需在目标环境中确认。

## 项目文件

| 文件 | 用途 |
| --- | --- |
| [HMA++.c](HMA++.c) | 模块信息、黑名单、系统调用钩子及加载与卸载逻辑 |
| [Makefile](Makefile) | 交叉编译与清理规则 |
| [LICENSE](LICENSE) | GNU GPL v3 许可证全文 |

## 维护与交流

作者因学业原因维护时间有限，项目已开源，后续更新视时间安排。欢迎 Star、Fork 和 Pull Request。

反馈问题时，请附上模块版本、设备架构、Android 与内核版本、KernelPatch 版本、复现步骤及相关 `[HMA++]` 日志，方便定位问题。

- Telegram 频道：<https://t.me/mizhipindao>
- Telegram 群组：<https://t.me/mizhichat>

## 许可证

本项目采用 [GNU General Public License v3.0](LICENSE)。
