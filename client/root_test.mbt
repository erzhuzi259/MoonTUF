///|
test "trusted root anchor opens only after valid self-signature" {
  let key = @testkit.signer(1)
  let raw = @testkit.root(1, key, [key])
  let client = open_trusted_root(raw, "2026-09-25T00:00:00Z").unwrap()
  assert_eq(client.root_version(), 1)
  assert_eq(client.next_root_name(), Some("2.root.json"))
  assert_true(client.finish_root_chain() is Ok(_))
  assert_false(client.ready())
}

///|
test "root rotation requires old and new authorized signatures" {
  let old_key = @testkit.signer(1)
  let new_key = @testkit.signer(2)
  let anchor = @testkit.root(1, old_key, [old_key])
  let client = open_trusted_root(anchor, "2026-09-25T00:00:00Z").unwrap()
  let valid = @testkit.root(2, new_key, [old_key, new_key])
  let advanced = client.advance_root(valid).unwrap()
  assert_eq(advanced.root_version(), 2)
  assert_eq(advanced.next_root_name(), Some("3.root.json"))
  let old_only = @testkit.root(2, new_key, [old_key])
  assert_true(client.advance_root(old_only) is Err(Trust(_)))
  let new_only = @testkit.root(2, new_key, [new_key])
  assert_true(client.advance_root(new_only) is Err(Trust(_)))
}

///|
test "root rotation rejects skipped versions and expiry at update start" {
  let key = @testkit.signer(3)
  let anchor = @testkit.root(1, key, [key])
  let client = open_trusted_root(anchor, "2026-09-25T00:00:00Z").unwrap()
  assert_true(
    client.advance_root(@testkit.root(3, key, [key]))
    is Err(VersionMismatch(_, _, _)),
  )
  let expired = @testkit.root(2, key, [key], expires="2026-09-25T00:00:00Z")
  let intermediate = client.advance_root(expired).unwrap()
  assert_true(intermediate.finish_root_chain() is Err(Expired("root")))
}

///|
test "root size and rotation budgets fail closed" {
  let key = @testkit.signer(4)
  let anchor = @testkit.root(1, key, [key])
  assert_true(
    open_trusted_root(
      anchor,
      "2026-09-25T00:00:00Z",
      budget=budgets(max_root_bytes=10),
    )
    is Err(ResourceLimit(_, _, _)),
  )
  let client = open_trusted_root(
    anchor,
    "2026-09-25T00:00:00Z",
    budget=budgets(max_root_rotations=1),
  ).unwrap()
  let first = client.advance_root(@testkit.root(2, key, [key])).unwrap()
  assert_true(
    first.advance_root(@testkit.root(3, key, [key]))
    is Err(RootRotationLimit(_)),
  )
}

///|
test "root key rotation keeps timestamp rollback baselines" {
  let old_key = @testkit.signer(50)
  let new_key = @testkit.signer(51)
  let old_targets = @testkit.empty_targets(5, old_key)
  let old_snapshot = @testkit.snapshot(5, 5, old_targets, old_key)
  let old_timestamp = @testkit.timestamp(5, 5, old_snapshot, old_key)
  let initial = open_trusted_root(
      @testkit.root(1, old_key, [old_key]),
      "2026-09-25T00:00:00Z",
    )
    .unwrap()
    .accept_timestamp(old_timestamp)
    .unwrap()
  let rotated = initial
    .advance_root(@testkit.root(2, new_key, [old_key, new_key]))
    .unwrap()
  assert_eq(rotated.timestamp_version(), None)
  let new_targets = @testkit.empty_targets(6, new_key)
  let new_snapshot = @testkit.snapshot(6, 6, new_targets, new_key)
  let old_version = @testkit.timestamp(4, 6, new_snapshot, new_key)
  assert_true(
    rotated.accept_timestamp(old_version) is Err(Rollback("timestamp", 5, 4)),
  )
  let old_snapshot_ref = @testkit.timestamp(6, 4, new_snapshot, new_key)
  assert_true(
    rotated.accept_timestamp(old_snapshot_ref)
    is Err(Rollback("timestamp.snapshot", 5, 4)),
  )
  let accepted = rotated
    .accept_timestamp(@testkit.timestamp(6, 6, new_snapshot, new_key))
    .unwrap()
  assert_eq(accepted.timestamp_version(), Some(6))
}
