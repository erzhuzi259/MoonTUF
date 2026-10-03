# October addition: trusted top-level inventory

`Client::top_level_inventory(prefix? = "", max_results? = 1024)` returns an all-or-error array of top-level target descriptors only after the entire current metadata chain passes freshness checks. An empty prefix selects all top-level targets; a nonempty safe path selects the exact path and descendants separated by `/`. Invalid paths, incomplete/expired chains and result limits return `ClientError`.

This is a discovery aid, not download authorization or an inventory of delegated roles. A caller must still resolve a selected target against current trusted state and verify candidate bytes before installation. The caller also remains responsible for the authenticated bootstrap root, trusted time, atomic staging and rollback-resistant local state.

Run `moon test client/inventory_test.mbt` for path, limit, incomplete-chain and expired-chain cases. The method scans `n` top-level descriptors in O(n) time; the model's copy-returning accessor temporarily holds O(n) descriptors plus the bounded result.

`Client::top_level_inventory_page(offset, page_size, prefix? = "")` serves the same trusted, top-level namespace as bounded pages. `offset` counts matching targets, `page_size` must be 1–4096, and the response includes `total` and `next_offset`. It rejects stale or incomplete metadata and unsafe prefixes. Each call scans O(n) descriptors and holds at most `page_size` results in addition to the model accessor's temporary copy. A caller must finish pagination against the same immutable trusted client state; after refresh, restart at offset zero. Run `moon test client/inventory_page_test.mbt` for ordering, empty tail pages, invalid bounds, and expiry.

The refresh path also distinguishes a missing next root (`Absent`) from a transport or storage failure (`Failure`). Only genuine absence may terminate a sequential root search; fetch failures propagate and cannot be mistaken for a valid end of the rotation chain. See [ADR 0004](adr/0004-distinguish-root-absence-from-fetch-failure.md).

## 十月第二轮：受信清单差异与缓存同步计划

`Client::diff_top_level_inventory(previous, prefix?, max_results?, max_changes?)` 比较完整链中的顶层目标，仅按长度和 SHA-256 分类新增、删除与内容变化，不比较 custom；两个客户端各用其宿主提供的时间检查有效期。宿主须确认两者属于同一仓库；该报告不是更新授权或回滚验证的替代品。

`plan_top_level_sync(cached, prefix?, max_targets?, max_cached?)` 将当前受信目标与宿主实际测得的本地指纹比较，返回 current、missing、changed、orphaned。缓存重复路径、非法路径/长度/指纹及超预算报错；orphaned 仅是指定命名空间内提示，不执行删除。委托目标须走原有委托解析；下载仍须校验实际字节后安装。运行 `moon run examples/offline --target js`。详见 [本轮审查与复杂度](SECOND_REVIEW.md) 和 [十月申报资料稿](../十月项目申报书.md)。
