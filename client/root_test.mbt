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
  assert_true(client.advance_root(@testkit.root(3, key, [key])) is
    Err(VersionMismatch(_, _, _)))
  let expired = @testkit.root(
    2,
    key,
    [key],
    expires="2026-09-25T00:00:00Z",
  )
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
    ) is Err(ResourceLimit(_, _, _)),
  )
  let client = open_trusted_root(
    anchor,
    "2026-09-25T00:00:00Z",
    budget=budgets(max_root_rotations=1),
  ).unwrap()
  let first = client.advance_root(@testkit.root(2, key, [key])).unwrap()
  assert_true(first.advance_root(@testkit.root(3, key, [key])) is Err(RootRotationLimit(_)))
}
