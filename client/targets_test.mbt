///|
fn complete_chain(key : @testkit.Signer, path : String, artifact : Bytes) -> Client {
  let targets = @testkit.targets(1, path, artifact, key)
  let snapshot = @testkit.snapshot(1, 1, targets, key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  .accept_timestamp(timestamp).unwrap()
  .accept_snapshot(snapshot).unwrap()
  .accept_targets(targets).unwrap()
}

///|
test "complete four-role chain exposes only described targets" {
  let key = @testkit.signer(13)
  let client = complete_chain(key, "apps/demo.bin", @utf8.encode("abc"))
  assert_true(client.ready())
  assert_eq(client.targets_version(), Some(1))
  assert_eq(client.top_level_target("apps/demo.bin").unwrap().length(), 3)
  assert_true(client.top_level_target("unknown.bin") is Err(TargetNotFound(_)))
  assert_true(client.top_level_target("../evil") is Err(InvalidPath(_)))
}

///|
test "targets raw bytes must match the trusted snapshot" {
  let key = @testkit.signer(14)
  let artifact = @utf8.encode("abc")
  let targets = @testkit.targets(1, "app.bin", artifact, key)
  let snapshot = @testkit.snapshot(1, 1, targets, key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  let client = open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
  ).unwrap().accept_timestamp(timestamp).unwrap().accept_snapshot(snapshot).unwrap()
  let tampered = @testkit.targets(1, "other.bin", artifact, key)
  assert_true(client.accept_targets(tampered) is Err(LengthMismatch(_, _, _) | HashMismatch(_)))
}

///|
test "targets cannot be used before all verification stages" {
  let key = @testkit.signer(15)
  let client = open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  assert_true(client.top_level_target("app.bin") is Err(MissingStage(_)))
  assert_true(client.accept_targets(@testkit.empty_targets(1, key)) is Err(MissingStage(_)))
}
