///|
test "top-level inventory respects namespace and result budget" {
  let client = complete_chain(
    @testkit.signer(213),
    "apps/demo.bin",
    @utf8.encode("abc"),
  )
  let all = client.top_level_inventory().unwrap()
  assert_eq(all.length(), 1)
  assert_eq(all[0].path(), "apps/demo.bin")
  assert_eq(client.top_level_inventory(prefix="apps").unwrap().length(), 1)
  assert_eq(
    client.top_level_inventory(prefix="apps/demo.bin").unwrap().length(),
    1,
  )
  assert_eq(client.top_level_inventory(prefix="app").unwrap().length(), 0)
  assert_eq(client.top_level_inventory(max_results=1).unwrap().length(), 1)
  assert_true(
    client.top_level_inventory(max_results=0) is Err(ResourceLimit(_, _, _)),
  )
  assert_true(
    client.top_level_inventory(prefix="../apps") is Err(InvalidPath(_)),
  )
}

///|
test "inventory rejects incomplete and stale chains" {
  let key = @testkit.signer(214)
  let root = open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  assert_true(root.top_level_inventory() is Err(MissingStage(_)))
  let client = complete_chain(key, "app.bin", @utf8.encode("abc"))
  let stale = client.begin_update("2041-01-01T00:00:00Z").unwrap()
  assert_true(stale.top_level_inventory() is Err(Expired(_)))
}

///|
test "inventory refuses partial results when namespace exceeds limit" {
  let key = @testkit.signer(215)
  let artifact = @utf8.encode("abc")
  let digest = @crypto.sha256_hex(artifact)
  let signed_json = "{\"_type\":\"targets\",\"spec_version\":\"1.0.0\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{\"apps/a.bin\":{\"length\":3,\"hashes\":{\"sha256\":\"\{digest}\"}},\"apps/b.bin\":{\"length\":3,\"hashes\":{\"sha256\":\"\{digest}\"}}}}"
  let targets = @testkit.signed_envelope(signed_json, [key])
  let snapshot = @testkit.snapshot(1, 1, targets, key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  let client = open_trusted_root(
      @testkit.root(1, key, [key]),
      "2026-09-25T00:00:00Z",
    )
    .unwrap()
    .accept_timestamp(timestamp)
    .unwrap()
    .accept_snapshot(snapshot)
    .unwrap()
    .accept_targets(targets)
    .unwrap()
  assert_true(
    client.top_level_inventory(prefix="apps", max_results=1)
    is Err(ResourceLimit(_, 2, 1)),
  )
  assert_eq(
    client
    .top_level_inventory(prefix="apps/a.bin", max_results=1)
    .unwrap()
    .length(),
    1,
  )
}
