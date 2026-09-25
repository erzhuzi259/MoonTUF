///|
test "verified target is returned only after exact length and digest match" {
  let key = @testkit.signer(16)
  let artifact = @utf8.encode("abc")
  let client = complete_chain(key, "apps/demo.bin", artifact)
  let verified = client.verify_top_level_target("apps/demo.bin", artifact).unwrap()
  assert_eq(verified.length(), 3)
  assert_eq(verified.sha256(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  assert_true(client.verify_top_level_target("apps/demo.bin", @utf8.encode("ab")) is
    Err(LengthMismatch(_, _, _)))
  assert_true(client.verify_top_level_target("apps/demo.bin", @utf8.encode("abd")) is
    Err(HashMismatch(_)))
}

///|
test "consistent target filename prefixes basename with trusted digest" {
  let key = @testkit.signer(17)
  let artifact = @utf8.encode("abc")
  let targets = @testkit.targets(1, "apps/demo.bin", artifact, key)
  let snapshot = @testkit.snapshot(1, 1, targets, key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  let client = open_trusted_root(
    @testkit.root(1, key, [key], consistent_snapshot=true),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  .accept_timestamp(timestamp).unwrap()
  .accept_snapshot(snapshot).unwrap()
  .accept_targets(targets).unwrap()
  assert_true(client.top_level_target_request_name("apps/demo.bin") is
    Ok("apps/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.demo.bin"))
}

///|
test "target bytes over caller budget are rejected before hashing" {
  let key = @testkit.signer(18)
  let artifact = @utf8.encode("abc")
  let targets = @testkit.targets(1, "a.bin", artifact, key)
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
  assert_true(client.verify_top_level_target("a.bin", artifact) is
    Err(ResourceLimit(_, _, _)))
}
