///|
test "streaming verifier accepts exact chunked target" {
  let key = @testkit.signer(30)
  let artifact = @utf8.encode("abc")
  let client = complete_chain(key, "models/weights.bin", artifact)
  let stream = client.open_top_level_stream("models/weights.bin").unwrap()
  assert_eq(stream.remaining(), 3)
  assert_true(stream.write(@utf8.encode("a")) is Ok(_))
  assert_true(stream.write(@utf8.encode("bc")) is Ok(_))
  let verified = stream.finish().unwrap()
  assert_eq(verified.length(), 3)
  assert_true(stream.write(@utf8.encode("")) is Err(AlreadyFinished))
  assert_true(stream.finish() is Err(AlreadyFinished))
}

///|
test "streaming verifier rejects short, long and wrong-digest data" {
  let key = @testkit.signer(31)
  let artifact = @utf8.encode("abc")
  let client = complete_chain(key, "firmware.bin", artifact)
  let short = client.open_top_level_stream("firmware.bin").unwrap()
  assert_true(short.write(@utf8.encode("ab")) is Ok(_))
  assert_true(short.finish() is Err(LengthMismatch(_, _, _)))
  let long = client.open_top_level_stream("firmware.bin").unwrap()
  assert_true(long.write(@utf8.encode("abcd")) is Err(LengthMismatch(_, _, _)))
  assert_eq(long.bytes_seen(), 0)
  let altered = client.open_top_level_stream("firmware.bin").unwrap()
  assert_true(altered.write(@utf8.encode("abd")) is Ok(_))
  assert_true(altered.finish() is Err(HashMismatch(_)))
}

///|
test "streaming verifier enforces total target budget" {
  let key = @testkit.signer(32)
  let artifact = @utf8.encode("abc")
  let targets = @testkit.targets(1, "model.bin", artifact, key)
  let snapshot = @testkit.snapshot(1, 1, targets, key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  let client = open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
    budget=budgets(max_target_bytes=2),
  ).unwrap()
  .accept_timestamp(timestamp).unwrap()
  .accept_snapshot(snapshot).unwrap()
  .accept_targets(targets).unwrap()
  assert_true(client.open_top_level_stream("model.bin") is Err(ResourceLimit(_, _, _)))
}
