///|
test "snapshot accepts a pinned, signed version" {
  let key = @testkit.signer(9)
  let artifact = @utf8.encode("abc")
  let targets = @testkit.targets(1, "app.bin", artifact, key)
  let snapshot = @testkit.snapshot(2, 1, targets, key)
  let timestamp = @testkit.timestamp(1, 2, snapshot, key)
  let client = open_trusted_root(
    @testkit.root(1, key, [key], consistent_snapshot=true),
    "2026-09-25T00:00:00Z",
  ).unwrap().accept_timestamp(timestamp).unwrap()
  let accepted = client.accept_snapshot(snapshot).unwrap()
  assert_eq(accepted.snapshot_version(), Some(2))
  assert_true(accepted.targets_request_name() is Ok("1.targets.json"))
  assert_false(accepted.ready())
}

///|
test "snapshot rejects raw hash and length mismatch before parsing" {
  let key = @testkit.signer(10)
  let targets = @testkit.empty_targets(1, key)
  let snapshot = @testkit.snapshot(1, 1, targets, key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  let client = open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
  ).unwrap().accept_timestamp(timestamp).unwrap()
  let same_length = @utf8.decode(snapshot) catch { _ => abort("fixture") }
  let tampered = same_length.replace(old="\"version\":1", new="\"version\":2")
  assert_true(client.accept_snapshot(@utf8.encode(tampered)) is Err(HashMismatch(_)))
  let longer = @utf8.encode(same_length + " ")
  assert_true(client.accept_snapshot(longer) is Err(LengthMismatch(_, _, _)))
}

///|
test "snapshot version must match trusted timestamp" {
  let key = @testkit.signer(11)
  let targets = @testkit.empty_targets(1, key)
  let snapshot = @testkit.snapshot(1, 1, targets, key)
  let timestamp = @testkit.timestamp(1, 2, snapshot, key)
  let client = open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
  ).unwrap().accept_timestamp(timestamp).unwrap()
  assert_true(client.accept_snapshot(snapshot) is Err(VersionMismatch("snapshot", _, _)))
}

///|
test "new snapshot cannot roll back targets metadata version" {
  let key = @testkit.signer(12)
  let artifact = @utf8.encode("abc")
  let targets2 = @testkit.targets(2, "app.bin", artifact, key)
  let snapshot1 = @testkit.snapshot(1, 2, targets2, key)
  let timestamp1 = @testkit.timestamp(1, 1, snapshot1, key)
  let client = open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
  ).unwrap().accept_timestamp(timestamp1).unwrap().accept_snapshot(snapshot1).unwrap()
  let targets1 = @testkit.targets(1, "app.bin", artifact, key)
  let snapshot2 = @testkit.snapshot(2, 1, targets1, key)
  let timestamp2 = @testkit.timestamp(2, 2, snapshot2, key)
  let staged = client.accept_timestamp(timestamp2).unwrap()
  assert_eq(staged.snapshot_version(), None)
  assert_true(staged.accept_snapshot(snapshot2) is
    Err(Rollback("snapshot.targets.json", 2, 1)))
}
