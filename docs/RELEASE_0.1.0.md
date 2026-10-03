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
- 完整四后端 release 构建/测试及离线场景正在验证，结果将在完成后补录。
- CI 使用 `--deny-warn`，现有编译器迁移警告仅定向基线：`-implicit_impl_as_method-test_unqualified_package-unused_package`；不声明完全无警告。
- GitHub 推送后的相关 CI、Mooncakes 发布、独立消费者安装和 GitHub Release 尚待本次发布流程完成后记录，不能把配置或链接当成成功证据。

## 保留的功能边界

发布不是第三方安全审计、TUF 一致性认证或赛事验收结论。当前仅支持已文档化的 JSON / Ed25519 / SHA-256 配置；宿主负责可信根、可信时间、传输、状态落盘及安装事务。上游 TUF 一致性套件适配及独立安全审查仍未完成。

申报资料保留空白参赛者与联系方式；依十月章程，申请人仍需核实并人工定稿。
