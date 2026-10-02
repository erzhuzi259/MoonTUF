///|
test "trusted inventory pages preserve matching target order" {
  let key = @testkit.signer(216)
  let artifact = @utf8.encode("abc")
  let digest = @crypto.sha256_hex(artifact)
  let signed_json = "{\"_type\":\"targets\",\"spec_version\":\"1.0.0\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{\"apps/a.bin\":{\"length\":3,\"hashes\":{\"sha256\":\"\{digest}\"}},\"apps/b.bin\":{\"length\":3,\"hashes\":{\"sha256\":\"\{digest}\"}},\"other/c.bin\":{\"length\":3,\"hashes\":{\"sha256\":\"\{digest}\"}}}}"
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
  let first = client.top_level_inventory_page(0, 1, prefix="apps").unwrap()
  assert_eq(first.total(), 2)
  assert_eq(first.items().length(), 1)
  assert_eq(first.next_offset(), Some(1))
  let second = client.top_level_inventory_page(1, 1, prefix="apps").unwrap()
  assert_eq(second.items().length(), 1)
  assert_eq(second.next_offset(), None)
  assert_true(first.items()[0].path() != second.items()[0].path())
  assert_eq(
    client
    .top_level_inventory_page(99, 1, prefix="apps")
    .unwrap()
    .items()
    .length(),
    0,
  )
}

///|
test "inventory page rejects stale state and unsafe parameters" {
  let key = @testkit.signer(217)
  let client = complete_chain(key, "apps/a.bin", @utf8.encode("abc"))
  assert_true(
    client.top_level_inventory_page(-1, 1) is Err(ResourceLimit(_, _, _)),
  )
  assert_true(
    client.top_level_inventory_page(0, 0) is Err(ResourceLimit(_, _, _)),
  )
  assert_true(
    client.top_level_inventory_page(0, 1, prefix="../apps")
    is Err(InvalidPath(_)),
  )
  let stale = client.begin_update("2041-01-01T00:00:00Z").unwrap()
  assert_true(stale.top_level_inventory_page(0, 1) is Err(Expired(_)))
}
