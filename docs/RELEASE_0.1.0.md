# MoonTUF 0.1.0 发布记录

日期：2026-10-03；维护账户：`erzhuzi259`。

## 发布配置

- 公开仓库：https://github.com/erzhuzi259/MoonTUF
- 包名：`erzhuzi259/moontuf@0.1.0`；默认分支：`main`。
- 私密漏洞报告：https://github.com/erzhuzi259/MoonTUF/security/advisories/new
- 原 51 条未推送提交在完整 bundle 校验后统一作者与提交者账户；内容、消息、父子关系和时间保持不变。原始 bundle 及提交映射保存在仓库外的本地发布备份中。
- 有效 MoonBit 共 7,180 行；排除测试、testkit、空行和行注释后，含可运行示例为 4,830 行。该口径不包含依赖或构建目录，不代表功能质量认证。

## 本地与外部验证

- 工具链：`moon 0.1.20260827`、`moonc v0.10.14+7d59c7ec9`。
- `moon fmt --check` 与四后端 `moon check` 已通过。
- Wasm、Wasm-GC、JS、Native 四后端 release 构建和完整测试通过，每后端 118/118。
- 默认 Wasm-GC、JS、Native release 三种离线示例执行通过，覆盖五类单制品场景与多制品 bundle。
- CI 使用 `--deny-warn`，现有编译器迁移警告仅定向基线：`-implicit_impl_as_method-test_unqualified_package-unused_package`；不声明完全无警告。
- 发布源码：`b8c7238e3c61ec76293ab68ee8e72a5e45be6018`。
- 发布源码 CI：[37110919503](https://github.com/erzhuzi259/MoonTUF/actions/runs/37110919503)，Windows / Ubuntu portable 与 Ubuntu Native 作业全部成功。
- Mooncakes 发布：`moon publish` 成功，服务端 `200 OK`；[公开包文档](https://mooncakes.io/docs/erzhuzi259/moontuf) HTTP 200。
- 发布 ZIP SHA-256：`e5245fd9d8b165a78d4ee976278b66c3867fabcaa79970ffe05c554adb7640f5`；100 个归档条目，无 `.git`、`.mooncakes`、`_build` 或本地发布备份目录。
- 独立消费工程用 `moon add erzhuzi259/moontuf@0.1.0` 从公共注册表下载，未使用本地路径依赖；JS 检查与运行通过，覆盖签名元数据链、篡改字节拒绝、流式目标验证、清单差异和缓存同步计划。
- GitHub Release：[v0.1.0](https://github.com/erzhuzi259/MoonTUF/releases/tag/v0.1.0)，非草稿；发布者与 annotated tag 的 tagger 均为 `erzhuzi259`，标签精确指向发布源码。
- 发布后的 main 只补录文档证据，不覆盖或重发 0.1.0。当前默认分支 CI 状态以 [Actions](https://github.com/erzhuzi259/MoonTUF/actions) 为准。

## 保留的功能边界

发布不是第三方安全审计、TUF 一致性认证或赛事验收结论。当前仅支持已文档化的 JSON / Ed25519 / SHA-256 配置；宿主负责可信根、可信时间、传输、状态落盘及安装事务。上游 TUF 一致性套件适配及独立安全审查仍未完成。

申报资料保留空白参赛者与联系方式；依十月章程，申请人仍需核实并人工定稿。
