///|
fn bundle_client(key : @testkit.Signer) -> @client.Client {
  let a = @utf8.encode("abc")
  let b = @utf8.encode("defg")
  let digest_a = @crypto.sha256_hex(a)
  let digest_b = @crypto.sha256_hex(b)
  let signed =
    "{\"_type\":\"targets\",\"spec_version\":\"1.0.0\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{\"plugins/core.bin\":{\"length\":3,\"hashes\":{\"sha256\":\"\{digest_a}\"}},\"plugins/data.bin\":{\"length\":4,\"hashes\":{\"sha256\":\"\{digest_b}\"}}}}"
  let targets = @testkit.signed_envelope(signed, [key])
  let snapshot = @testkit.snapshot(1, 1, targets, key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  @client.open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  .accept_timestamp(timestamp).unwrap()
  .accept_snapshot(snapshot).unwrap()
  .accept_targets(targets).unwrap()
}

///|
test "bundle plan validates all files under one trusted snapshot" {
  let key = @testkit.signer(44)
  let client = bundle_client(key)
  let rules = bundle_policy(policy(prefix="plugins").unwrap(), max_total_bytes=16L).unwrap()
  let load = fn(_ : String) -> Bytes? { None }
  let plan = plan_bundle(
    client,
    ["plugins/core.bin", "plugins/data.bin"],
    rules,
    load,
  ).unwrap()
  assert_eq(plan.tickets().length(), 2)
  assert_eq(plan.total_bytes(), 7L)
  let verified = verify_bundle(
    client,
    plan,
    [@utf8.encode("abc"), @utf8.encode("defg")],
    load,
  ).unwrap()
  assert_eq(verified.length(), 2)
}

///|
test "bundle plan rejects duplicates and total budget overrun" {
  let key = @testkit.signer(45)
  let client = bundle_client(key)
  let rules = bundle_policy(policy(prefix="plugins").unwrap(), max_total_bytes=6L).unwrap()
  let load = fn(_ : String) -> Bytes? { None }
  assert_true(
    plan_bundle(client, ["plugins/core.bin", "plugins/core.bin"], rules, load) is
    Err(DuplicatePath(_)),
  )
  assert_true(
    plan_bundle(client, ["plugins/core.bin", "plugins/data.bin"], rules, load) is
    Err(TotalTooLarge(7L, 6L)),
  )
}

///|
test "bundle plan records already installed targets without downloading" {
  let key = @testkit.signer(46)
  let client = bundle_client(key)
  let rules = bundle_policy(policy(prefix="plugins").unwrap()).unwrap()
  let load = fn(_ : String) -> Bytes? { None }
  let plan = plan_bundle(
    client,
    ["plugins/core.bin", "plugins/data.bin"],
    rules,
    load,
    installed=[("plugins/core.bin", @crypto.sha256_hex(@utf8.encode("abc")))],
  ).unwrap()
  assert_eq(plan.current_paths(), ["plugins/core.bin"])
  assert_eq(plan.tickets().length(), 1)
  assert_eq(plan.total_bytes(), 4L)
}
