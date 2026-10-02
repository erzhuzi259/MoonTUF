# October addition: trusted top-level inventory

`Client::top_level_inventory(prefix? = "", max_results? = 1024)` returns an all-or-error array of top-level target descriptors only after the entire current metadata chain passes freshness checks. An empty prefix selects all top-level targets; a nonempty safe path selects the exact path and descendants separated by `/`. Invalid paths, incomplete/expired chains and result limits return `ClientError`.

This is a discovery aid, not download authorization or an inventory of delegated roles. A caller must still resolve a selected target against current trusted state and verify candidate bytes before installation. The caller also remains responsible for the authenticated bootstrap root, trusted time, atomic staging and rollback-resistant local state.

Run `moon test client/inventory_test.mbt` for path, limit, incomplete-chain and expired-chain cases. The method scans `n` top-level descriptors in O(n) time; the model's copy-returning accessor temporarily holds O(n) descriptors plus the bounded result.

`Client::top_level_inventory_page(offset, page_size, prefix? = "")` serves the same trusted, top-level namespace as bounded pages. `offset` counts matching targets, `page_size` must be 1–4096, and the response includes `total` and `next_offset`. It rejects stale or incomplete metadata and unsafe prefixes. Each call scans O(n) descriptors and holds at most `page_size` results in addition to the model accessor's temporary copy. A caller must finish pagination against the same immutable trusted client state; after refresh, restart at offset zero. Run `moon test client/inventory_page_test.mbt` for ordering, empty tail pages, invalid bounds, and expiry.

The refresh path also distinguishes a missing next root (`Absent`) from a transport or storage failure (`Failure`). Only genuine absence may terminate a sequential root search; fetch failures propagate and cannot be mistaken for a valid end of the rotation chain. See [ADR 0004](adr/0004-distinguish-root-absence-from-fetch-failure.md).
