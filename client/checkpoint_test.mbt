///|
test "checkpoint round-trip reverifies complete chain" {
  let key = @testkit.signer(33)
  let client = complete_chain(key, "app.bin", @utf8.encode("abc"))
  let encoded = client.checkpoint().unwrap()
  let root = @testkit.root(1, key, [key])
  let restored = restore_checkpoint(encoded, root, "2026-09-26T00:00:00Z").unwrap()
  assert_true(restored.ready())
  assert_eq(restored.root_version(), 1)
  assert_eq(restored.top_level_target("app.bin").unwrap().length(), 3)
}

///|
test "checkpoint detects corruption and truncation" {
  let key = @testkit.signer(34)
  let client = complete_chain(key, "app.bin", @utf8.encode("abc"))
  let encoded = client.checkpoint().unwrap()
  let damaged = encoded.to_array()
  damaged[damaged.length() - 1] = 0
  let root = @testkit.root(1, key, [key])
  assert_true(
    restore_checkpoint(Bytes::from_array(damaged), root, "2026-09-26T00:00:00Z")
    is Err(CheckpointMalformed(_)),
  )
  assert_true(
    restore_checkpoint(@utf8.encode("MTUF1"), root, "2026-09-26T00:00:00Z")
    is Err(CheckpointMalformed(_)),
  )
}

///|
test "expired restored metadata remains history but cannot authorize targets" {
  let key = @testkit.signer(35)
  let client = complete_chain(key, "app.bin", @utf8.encode("abc"))
  let encoded = client.checkpoint().unwrap()
  let root = @testkit.root(1, key, [key])
  let restored = restore_checkpoint(encoded, root, "2031-01-01T00:00:00Z").unwrap()
  assert_false(restored.ready())
  assert_true(restored.top_level_target("app.bin") is Err(MissingStage(_)))
}

///|
test "incomplete metadata chain cannot be checkpointed" {
  let key = @testkit.signer(36)
  let client = open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  assert_true(client.checkpoint() is Err(MissingStage(_)))
}

///|
test "checkpoint cannot replace out-of-band root of trust" {
  let key = @testkit.signer(37)
  let other = @testkit.signer(38)
  let client = complete_chain(key, "app.bin", @utf8.encode("abc"))
  let encoded = client.checkpoint().unwrap()
  let wrong_root = @testkit.root(1, other, [other])
  assert_true(
    restore_checkpoint(encoded, wrong_root, "2026-09-26T00:00:00Z")
    is Err(CheckpointRootMismatch),
  )
}
