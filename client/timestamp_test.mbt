///|
fn timestamp_fixture(
  version : Int,
  snapshot_version : Int,
  key : @testkit.Signer,
) -> Bytes {
  let artifact = @utf8.encode("abc")
  let targets = @testkit.targets(1, "apps/demo.bin", artifact, key)
  let snapshot = @testkit.snapshot(snapshot_version, 1, targets, key)
  @testkit.timestamp(version, snapshot_version, snapshot, key)
}

///|
test "timestamp signature, expiry and pinned snapshot are enforced" {
  let key = @testkit.signer(5)
  let client = open_trusted_root(
    @testkit.root(1, key, [key], consistent_snapshot=true),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  let updated = client.accept_timestamp(timestamp_fixture(1, 2, key)).unwrap()
  assert_eq(updated.timestamp_version(), Some(1))
  assert_true(updated.snapshot_request_name() is Ok("2.snapshot.json"))
  assert_false(updated.ready())
  let expired_timestamp = @testkit.timestamp(
    2,
    2,
    @utf8.encode("dummy"),
    key,
    expires="2026-09-25T00:00:00Z",
  )
  assert_true(
    updated.accept_timestamp(expired_timestamp) is Err(Expired("timestamp")),
  )
}

///|
test "timestamp rejects same version and snapshot reference rollback" {
  let key = @testkit.signer(6)
  let client = open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  let first = client.accept_timestamp(timestamp_fixture(2, 3, key)).unwrap()
  assert_true(
    first.accept_timestamp(timestamp_fixture(2, 3, key))
    is Err(Unchanged("timestamp", 2)),
  )
  assert_true(
    first.accept_timestamp(timestamp_fixture(3, 2, key))
    is Err(Rollback("timestamp.snapshot", _, _)),
  )
  assert_true(
    first.accept_timestamp(timestamp_fixture(1, 4, key))
    is Err(Rollback("timestamp", _, _)),
  )
}

///|
test "timestamp refuses an unsigned candidate" {
  let key = @testkit.signer(7)
  let other = @testkit.signer(8)
  let client = open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  assert_true(
    client.accept_timestamp(timestamp_fixture(1, 1, other)) is Err(Trust(_)),
  )
}

///|
test "same-version timestamp cannot hide expiry" {
  let key = @testkit.signer(9)
  let client = open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  let first = client.accept_timestamp(timestamp_fixture(2, 3, key)).unwrap()
  let expired_timestamp = @testkit.timestamp(
    2,
    3,
    @utf8.encode("dummy"),
    key,
    expires="2026-09-25T00:00:00Z",
  )
  assert_true(
    first.accept_timestamp(expired_timestamp) is Err(Expired("timestamp")),
  )
}

///|
test "begin update preserves baselines and rejects clock rollback" {
  let key = @testkit.signer(10)
  let client = open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  let first = client.accept_timestamp(timestamp_fixture(1, 1, key)).unwrap()
  assert_true(
    first.begin_update("2026-09-24T23:59:59Z") is Err(ClockRollback(_, _)),
  )
  let second = first.begin_update("2026-09-26T00:00:00Z").unwrap()
  assert_eq(second.timestamp_version(), Some(1))
  assert_true(
    second.accept_timestamp(timestamp_fixture(1, 1, key))
    is Err(Unchanged("timestamp", 1)),
  )
}
