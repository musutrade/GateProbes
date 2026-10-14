# Native Rust 插件独立安装

GateProbes 负责插件安装、升级、回滚、固定版本、资产名称和签名身份。
GateHouse 安装器只安装 Core；当前源码中的旧插件参数在任何下载或替换前
给出迁移错误。历史标签中的安装器、发行资产和签名身份保持原样。

先自行提供可信的 Cosign，再从完整提交下载安装器并校验脚本摘要：

~~~bash
curl --fail --show-error --location --proto '=https' --tlsv1.2 \
  -o /tmp/gateprobes-install-native.sh \
  https://raw.githubusercontent.com/musutrade/GateProbes/1507805205944229950e0fe57d4fe1f17fc3e130/tools/install/install-native.sh
printf '%s  %s\n' 317e7f98e3863d44d32640106091596e227be0795463dd81adcd26ef6797bce6 /tmp/gateprobes-install-native.sh | sha256sum --check
bash /tmp/gateprobes-install-native.sh --version 0.1.0-rc.8 \
  --install-dir "$HOME/.local/bin"
~~~

macOS 的脚本摘要校验改用 shasum -a 256 --check，Windows 使用 Bash。
版本必须显式提供；不执行 main/latest 脚本，不读取环境默认插件版本，也不
跨仓库或签名身份回退。缺少 Bash、curl/wget、SHA256 或 Cosign 时仅诊断，
不会安装或替换 Rust、LLVM、Python、Cosign 等工具。
测量运行依赖见 [native 合约](https://github.com/musutrade/GateHouse/blob/v0.5.0/docs/quality/native-external-toolchain.md)。

安装器校验签名的 SHA256SUMS、目标二进制的摘要与签名，签名必须绑定
GitHub Actions OIDC 和所选标签的 GateProbes native-collector-release.yml。
RC8 仍是历史可变 prerelease，额外固定原清单摘要
d8f2302dc56108b6db8d971bed18c7d3bf0265506768663de8fb91d27011444b；
同标签即使有签名的不同内容也拒绝。不重建、覆盖或重新签名旧发行。

Linux x86_64、macOS Intel/ARM、Windows x86_64 对应固定平台资产，无平台或
ABI 回退。验证完成后在私有绝对目录内原子替换；拒绝软链接、路径穿越和
组/其他用户可写目录。下载、签名、复制、权限设置、重命名或信号中断失败
保留原程序并清理本次操作自己的临时文件。

升级或回滚均运行同一已校验安装器，将 --version 指定为已发布且经过
兼容性审查的新版本或原来记录的版本，并指定原安装目录。
目前 GateProbes 只有 native RC8；两版本升级/回滚测试使用明确标识的签名
fixture，不表示 GateProbes RC4 已发布。旧 Harness-Gate 版本必须使用其
原始标签安装器和签名，不会自动跨身份查找。安装不修改配置或基线。

| 旧 Core 参数 | 迁移 |
| --- | --- |
| --rust-only --rust-version X | GateProbes 安装器 --version X |
| --with-rust --rust-version X | 分别执行 Core 和插件安装器 |
| --rust-root DIR | 插件 --install-dir DIR/bin |
| HARNESS_GATE_RUST_VERSION=X | 显式 --version X |
| --cache-dir DIR | 在 PATH 提供可信验证器，无自动下载缓存 |
| 历史 --offline | 使用历史标签安装器 |

Core 兼容执行入口在本次变更退出，只保留诊断；唯一可编辑的插件安装实现
位于 GateProbes tools/install/install-native.sh。协议和测量定义不变；
requiredness、阈值、baseline/debt/ratchet、最终决策和发布权威仍属 Core。

四平台调度、升级/回滚、错误仓库/标签/工作流、篡改/缺失签名、缺失验证器、
环境污染、原子失败恢复和 HUP/INT/TERM 清理测试由 CI 必须执行。
完整信任声明、测试边界和未来发行要求见[英文指南](native-installation.md)。
