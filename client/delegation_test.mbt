///|
fn delegated_chain(
  top_key : @testkit.Signer,
  delegated_key : @testkit.Signer,
  delegated_raw : Bytes,
) -> Client {
  let top = @testkit.top_with_delegation(
    1, "apps", "apps/*.bin", top_key, delegated_key,
  )
  let snapshot = @testkit.snapshot_with_delegation(
    1, top, "apps", delegated_raw, top_key,
  )
  let timestamp = @testkit.timestamp(1, 1, snapshot, top_key)
  open_trusted_root(
    @testkit.root(1, top_key, [top_key], consistent_snapshot=true),
    "2026-09-25T00:00:00Z",
  )
  .unwrap()
  .accept_timestamp(timestamp)
  .unwrap()
  .accept_snapshot(snapshot)
  .unwrap()
  .accept_targets(top)
  .unwrap()
}

///|
test "delegated target requires authorized signature and snapshot pin" {
  let top_key = @testkit.signer(19)
  let delegated_key = @testkit.signer(20)
  let artifact = @utf8.encode("abc")
  let delegated = @testkit.targets(1, "apps/demo.bin", artifact, delegated_key)
  let client = delegated_chain(top_key, delegated_key, delegated)
  let loader = fn(name : String) -> Bytes? {
    if name == "1.apps.json" {
      Some(delegated)
    } else {
      None
    }
  }
  assert_eq(client.find_target("apps/demo.bin", loader).unwrap().length(), 3)
  assert_eq(
    client.find_target_detail("apps/demo.bin", loader).unwrap().role_chain(),
    ["targets", "apps"],
  )
  assert_eq(
    client.verify_target("apps/demo.bin", artifact, loader).unwrap().length(),
    3,
  )
  assert_true(
    client.target_request_name("apps/demo.bin", loader)
    is Ok(
      "apps/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.demo.bin"
    ),
  )
  assert_true(
    client.find_target("apps/nested/demo.bin", loader) is Err(TargetNotFound(_)),
  )
}

///|
test "delegation loader absence and wrong signing key fail closed" {
  let top_key = @testkit.signer(21)
  let delegated_key = @testkit.signer(22)
  let attacker = @testkit.signer(23)
  let artifact = @utf8.encode("abc")
  let wrong = @testkit.targets(1, "apps/demo.bin", artifact, attacker)
  let client = delegated_chain(top_key, delegated_key, wrong)
  let missing = fn(_ : String) -> Bytes? { None }
  assert_true(
    client.find_target("apps/demo.bin", missing) is Err(MetadataUnavailable(_)),
  )
  let supplied = fn(_ : String) -> Bytes? { Some(wrong) }
  assert_true(client.find_target("apps/demo.bin", supplied) is Err(Trust(_)))
}

///|
test "delegation visit budget prevents unbounded graph traversal" {
  let top_key = @testkit.signer(24)
  let delegated_key = @testkit.signer(25)
  let artifact = @utf8.encode("abc")
  let delegated = @testkit.targets(1, "apps/demo.bin", artifact, delegated_key)
  let top = @testkit.top_with_delegation(
    1, "apps", "apps/*.bin", top_key, delegated_key,
  )
  let snapshot = @testkit.snapshot_with_delegation(
    1, top, "apps", delegated, top_key,
  )
  let timestamp = @testkit.timestamp(1, 1, snapshot, top_key)
  let client = open_trusted_root(
      @testkit.root(1, top_key, [top_key]),
      "2026-09-25T00:00:00Z",
      budget=budgets(max_delegated_roles=1),
    )
    .unwrap()
    .accept_timestamp(timestamp)
    .unwrap()
    .accept_snapshot(snapshot)
    .unwrap()
    .accept_targets(top)
    .unwrap()
  let load = fn(_ : String) -> Bytes? { Some(delegated) }
  assert_eq(client.find_target("apps/demo.bin", load).unwrap().length(), 3)
}
