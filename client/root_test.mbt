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
test "online key rotation clears fast-forwarded timestamp baseline" {
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
    .finish_root_chain()
    .unwrap()
  assert_eq(rotated.timestamp_version(), None)
  let recovered_targets = @testkit.empty_targets(4, new_key)
  let recovered_snapshot = @testkit.snapshot(4, 4, recovered_targets, new_key)
  let recovered_timestamp = @testkit.timestamp(
    4, 4, recovered_snapshot, new_key,
  )
  let accepted = rotated.accept_timestamp(recovered_timestamp).unwrap()
  assert_eq(accepted.timestamp_version(), Some(4))
  assert_eq(
    accepted.accept_snapshot(recovered_snapshot).unwrap().snapshot_version(),
    Some(4),
  )
}

///|
test "root-only rotation retains online rollback baselines" {
  let old_key = @testkit.signer(52)
  let new_root_key = @testkit.signer(53)
  let old_id = old_key.keyid()
  let new_id = new_root_key.keyid()
  let old_role = "{\"keyids\":[\"\{old_id}\"],\"threshold\":1}"
  let root_role = "{\"keyids\":[\"\{new_id}\"],\"threshold\":1}"
  let signed = "{\"_type\":\"root\",\"spec_version\":\"1.0.0\",\"version\":2,\"expires\":\"2030-01-01T00:00:00Z\",\"keys\":{\"\{old_id}\":\{old_key.key_json()},\"\{new_id}\":\{new_root_key.key_json()}},\"roles\":{\"root\":\{root_role},\"timestamp\":\{old_role},\"snapshot\":\{old_role},\"targets\":\{old_role}}}"
  let candidate = @testkit.signed_envelope(signed, [old_key, new_root_key])
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
    .accept_snapshot(old_snapshot)
    .unwrap()
    .accept_targets(old_targets)
    .unwrap()
  let rotated = initial.advance_root(candidate).unwrap()
  assert_false(rotated.ready())
  let finished = rotated.finish_root_chain().unwrap()
  assert_true(finished.ready())
  let lower = @testkit.timestamp(4, 4, old_snapshot, old_key)
  assert_true(
    finished.accept_timestamp(lower) is Err(Rollback("timestamp", 5, 4)),
  )
  let new_targets = @testkit.empty_targets(6, old_key)
  let new_snapshot = @testkit.snapshot(6, 6, new_targets, old_key)
  let higher = @testkit.timestamp(6, 6, new_snapshot, old_key)
  assert_eq(
    finished.accept_timestamp(higher).unwrap().timestamp_version(),
    Some(6),
  )
  let load = fn(name : String) -> Bytes? {
    match name {
      "2.root.json" => Some(candidate)
      "timestamp.json" => Some(old_timestamp)
      _ => None
    }
  }
  let outcome = initial.refresh(load)
  assert_true(outcome.status() is Unchanged)
  assert_true(outcome.client().ready())
}

///|
test "snapshot-only key rotation also clears online baselines" {
  let old_key = @testkit.signer(54)
  let new_snapshot_key = @testkit.signer(55)
  let old_id = old_key.keyid()
  let new_id = new_snapshot_key.keyid()
  let old_role = "{\"keyids\":[\"\{old_id}\"],\"threshold\":1}"
  let new_role = "{\"keyids\":[\"\{new_id}\"],\"threshold\":1}"
  let signed = "{\"_type\":\"root\",\"spec_version\":\"1.0.0\",\"version\":2,\"expires\":\"2030-01-01T00:00:00Z\",\"keys\":{\"\{old_id}\":\{old_key.key_json()},\"\{new_id}\":\{new_snapshot_key.key_json()}},\"roles\":{\"root\":\{old_role},\"timestamp\":\{old_role},\"snapshot\":\{new_role},\"targets\":\{old_role}}}"
  let candidate = @testkit.signed_envelope(signed, [old_key])
  let old_targets = @testkit.empty_targets(5, old_key)
  let old_snapshot = @testkit.snapshot(5, 5, old_targets, old_key)
  let initial = open_trusted_root(
      @testkit.root(1, old_key, [old_key]),
      "2026-09-25T00:00:00Z",
    )
    .unwrap()
    .accept_timestamp(@testkit.timestamp(5, 5, old_snapshot, old_key))
    .unwrap()
  let rotated = initial
    .advance_root(candidate)
    .unwrap()
    .finish_root_chain()
    .unwrap()
  let recovered_targets = @testkit.empty_targets(4, old_key)
  let recovered_snapshot = @testkit.snapshot(
    4, 4, recovered_targets, new_snapshot_key,
  )
  let recovered_timestamp = @testkit.timestamp(
    4, 4, recovered_snapshot, old_key,
  )
  let accepted = rotated.accept_timestamp(recovered_timestamp).unwrap()
  assert_eq(accepted.timestamp_version(), Some(4))
  assert_eq(
    accepted.accept_snapshot(recovered_snapshot).unwrap().snapshot_version(),
    Some(4),
  )
}
