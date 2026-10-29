# 批量制品验证与元数据到期预检

## 同一可信状态下的批量制品验证

`Client::verify_batch(candidates, load, max_targets~, max_total_bytes~)` 首先检查
当前完整且新鲜的信任链，再检查所有显式 `(path, bytes)` 的唯一安全路径、单体大小、
总字节预算。全部预检通过后复用授权解析计划，逐项检查描述符长度和受支持哈希。
已有 admission 包的 BundlePlan/verify_bundle 提供策略和安装状态集成；
新增入口针对已下载字节的独立验证，在同一批中缓存委托元数据，提前检查整个输入预算，
不要求构建 admission tickets。需要策略门禁或流式验证时仍使用既有 admission 接口。
返回 `VerifiedBatch` 的独立目标数组、总长度、根哈希和快照版本；任何失败均不返回
部分批次。空批次仍需新鲜完整信任链。默认最多 256 项、256 MiB，总限制可配置。

用于应用与插件协同更新、模型与词表成套分发、固件附带配置的下载后校验。
load 仅加载委托元数据；网络、持久化、原子安装和回滚切换由宿主实现。
“全部成功才返回”不能使宿主文件操作自动具备事务性。
在原有 resolve_plan 成本之外，哈希线性于总字节 B，结果存储 O(T)，路径集合
O(T) 期望空间；已有不可变 Bytes 不重新复制整份内容，受支持哈希计算会处理内容。

## 四个顶层角色的到期预检

`Client::expiry_horizon(horizon)` 检查合法 UTC 时间且不早于当前更新起始时间，
要求当前信任链仍然新鲜。按 root/timestamp/snapshot/targets 固定顺序返回角色、版本、
到期时间和 `due()`；在 horizon 恰好到期也标记为 true。
该操作只读取当前已接受的四个顶层角色，不枚举未保留的委托角色。

用于离线维护窗口、镜像刷新计划和制品更新告警。它不推进可信时钟、不延长有效期、
不批准未来使用；实际未来更新仍调用 begin_update 并重新完成校验。
新增计算为常数时间/空间，信任链新鲜性检查使用现有固定四角色逻辑。

## 验证范围

`client/verified_batch_test.mbt` 检查正确与篡改字节、重复路径、预算先于加载回调、
结果数组隔离、精确到期边界、时钟回退、非法日期与已过期空批次。
示例使用合成签名密钥，只用于离线演示，不能作为生产根密钥。

## 本地复现

要求 moonc >= 0.10.16。在本地源码目录执行：

```sh
moon update
python tools/verify_toolchain.py
moon check --target all --deny-warn
moon build --target all --deny-warn
moon test --target all --deny-warn
moon run examples/batch_preflight --target wasm-gc --deny-warn
moon run examples/batch_preflight --target native --deny-warn
```

Windows 如遇 OCaml 扩展路径问题，使用仓库提供的 `tools/windows/moon.ps1`
代替 `moon`；没有该脚本的仓库建议在 Linux/WSL 环境运行上述命令。
这些是源码工作区新增 API，现有已发布版本号未变；发布新版本后才可从 Mooncakes
安装取得这些新增功能。全部示例为可运行断言，不代表已有生产部署。
