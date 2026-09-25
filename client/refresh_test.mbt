///|
test "one-shot refresh composes four-role verification" {
  let key = @testkit.signer(26)
  let artifact = @utf8.encode("abc")
  let targets = @testkit.targets(1, "apps/demo.bin", artifact, key)
  let snapshot = @testkit.snapshot(1, 1, targets, key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  let client = open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  let load = fn(name : String) -> Bytes? {
    match name {
      "timestamp.json" => Some(timestamp)
      "snapshot.json" => Some(snapshot)
      "targets.json" => Some(targets)
      _ => None
    }
  }
  let outcome = client.refresh(load)
  assert_true(outcome.status() is Complete)
  assert_true(outcome.client().ready())
  assert_eq(outcome.accepted().length(), 3)
}

///|
test "refresh returns partial trusted state after later fetch failure" {
  let key = @testkit.signer(27)
  let snapshot = @testkit.snapshot(1, 1, @testkit.empty_targets(1, key), key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  let client = open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  let load = fn(name : String) -> Bytes? {
    if name == "timestamp.json" {
      Some(timestamp)
    } else {
      None
    }
  }
  let outcome = client.refresh(load)
  assert_true(outcome.status() is Failed(MetadataUnavailable("snapshot.json")))
  assert_eq(outcome.client().timestamp_version(), Some(1))
  assert_eq(outcome.client().snapshot_version(), None)
  assert_eq(outcome.accepted().length(), 1)
}

///|
test "refresh can rotate root then validate metadata with new key" {
  let old_key = @testkit.signer(28)
  let new_key = @testkit.signer(29)
  let new_root = @testkit.root(2, new_key, [old_key, new_key])
  let targets = @testkit.empty_targets(1, new_key)
  let snapshot = @testkit.snapshot(1, 1, targets, new_key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, new_key)
  let client = open_trusted_root(
    @testkit.root(1, old_key, [old_key]),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  let load = fn(name : String) -> Bytes? {
    match name {
      "2.root.json" => Some(new_root)
      "timestamp.json" => Some(timestamp)
      "snapshot.json" => Some(snapshot)
      "targets.json" => Some(targets)
      _ => None
    }
  }
  let outcome = client.refresh(load)
  assert_true(outcome.status() is Complete)
  assert_eq(outcome.client().root_version(), 2)
  assert_eq(outcome.accepted().length(), 4)
}
