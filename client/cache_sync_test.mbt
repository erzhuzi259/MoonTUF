///|
test "inventory differences distinguish content replacement from path replacement" {
  let key = @testkit.signer(218)
  let old = complete_chain(key, "apps/a.bin", b"abc")
  let new = complete_chain(key, "apps/a.bin", b"xyz")
  let delta = new.diff_top_level_inventory(old).unwrap()
  assert_eq(delta.changed().length(), 1)
  assert_eq(delta.changed()[0].before().sha256(), @crypto.sha256_hex(b"abc"))
  assert_eq(delta.changed()[0].after().sha256(), @crypto.sha256_hex(b"xyz"))
  assert_eq(
    old.diff_top_level_inventory(old, max_changes=0).unwrap().unchanged(),
    1,
  )
  assert_true(
    new.diff_top_level_inventory(old, max_changes=0)
    is Err(ResourceLimit(_, _, _)),
  )
  let moved = complete_chain(key, "apps/b.bin", b"abc")
  let relocation = moved.diff_top_level_inventory(old).unwrap()
  assert_eq(relocation.added()[0].path(), "apps/b.bin")
  assert_eq(relocation.removed()[0].path(), "apps/a.bin")
  assert_eq(relocation.changed().length(), 0)
  let detached = relocation.added()
  detached.clear()
  assert_eq(relocation.added().length(), 1)
}

///|
test "sync plan reports missing changed current and namespace scoped orphaned entries" {
  let client = complete_chain(@testkit.signer(219), "apps/a.bin", b"abc")
  assert_eq(client.plan_top_level_sync([]).unwrap().missing().length(), 1)
  let fingerprint : CachedTarget = {
    path: "apps/a.bin",
    length: 3L,
    sha256: @crypto.sha256_hex(b"abc"),
  }
  let same = client.plan_top_level_sync([fingerprint]).unwrap()
  assert_eq(same.current(), ["apps/a.bin"])
  assert_eq(same.changed().length(), 0)
  let plan = client
    .plan_top_level_sync(
      [
        { ..fingerprint, sha256: @crypto.sha256_hex(b"xyz"), },
        { ..fingerprint, path: "apps/old.bin", },
        { ..fingerprint, path: "other/keep.bin", },
      ],
      prefix="apps",
    )
    .unwrap()
  assert_eq(plan.changed()[0].path(), "apps/a.bin")
  assert_eq(plan.orphaned(), ["apps/old.bin"])
  let copy = plan.orphaned()
  copy.clear()
  assert_eq(plan.orphaned(), ["apps/old.bin"])
  let wrong_length = client
    .plan_top_level_sync([{ ..fingerprint, length: 4L, }])
    .unwrap()
  assert_eq(wrong_length.changed().length(), 1)
}

///|
test "cache planner rejects malformed ambiguous over budget and stale inputs" {
  let client = complete_chain(@testkit.signer(220), "apps/a.bin", b"abc")
  let item : CachedTarget = {
    path: "apps/a.bin",
    length: 3L,
    sha256: @crypto.sha256_hex(b"abc"),
  }
  assert_true(
    client.plan_top_level_sync([item, item]) is Err(DuplicateCachedPath(_)),
  )
  assert_true(
    client.plan_top_level_sync([item], max_cached=0) is Err(CacheLimit(_)),
  )
  assert_true(
    client.plan_top_level_sync([{ ..item, path: "../a", }])
    is Err(InvalidCacheEntry(_)),
  )
  assert_true(
    client.plan_top_level_sync([{ ..item, length: -1L, }])
    is Err(InvalidCacheEntry(_)),
  )
  assert_true(
    client.plan_top_level_sync([{ ..item, sha256: "not-a-digest", }])
    is Err(InvalidCacheEntry(_)),
  )
  let stale = client.begin_update("2041-01-01T00:00:00Z").unwrap()
  assert_true(stale.plan_top_level_sync([]) is Err(Client(Expired(_))))
  assert_true(client.diff_top_level_inventory(stale) is Err(Expired(_)))
  assert_true(
    client.plan_top_level_sync([], prefix="../apps")
    is Err(Client(InvalidPath(_))),
  )
}
