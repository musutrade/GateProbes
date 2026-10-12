# 原生 Rust/MIR collector 0.1.0-rc.8

RC8 是 GateProbes 发布链发布的第一个原生 collector 预发布版本。采集行为与 RC7 相同；本版本的变化全部在发布与构建链路上。

- 从迁入 GateProbes 的源码构建四个平台的原生可执行文件：Linux x86-64、macOS Intel、macOS Apple Silicon、Windows x86-64。
- 每个平台在打包前对着固定的 Core 0.4.8 发行版二进制运行完整验收（23 项）与零跳过助手测试；不编译 Core 源码。
- 公开产物包含四个平台的二进制、CycloneDX SBOM、SHA256SUMS 与 `release-inventory.json`。
- 元数据以 Sigstore 无密钥（keyless）身份签名，证书身份绑定本仓库的发布 workflow；同时提供 GitHub 构建来源证明（attestation）。
- 发布模式把驱动编译为 release 配置，并以 `--target` 断言每个 runner 的编译主机与其产物平台一致。

签名身份从旧仓库的发布 workflow 变更为本仓库的发布 workflow。Core 的安装与信任仍固定旧身份，切换到新身份是后续独立步骤；在那之前本版本通过本仓库的 release 资产直接取得。旧仓库的发布入口与既有固定产物保持不变。

外部环境仍须提供 Rust 1.97.1、匹配的 LLVM 工具与 Python 3.12+。MIR 指标包含编译器生成控制流，与独立 Rust source-risk 的源码指标是不同序列，不能直接混用。RC8 不更改质量阈值，也不自动批准项目绑定或基线。
