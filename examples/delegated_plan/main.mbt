///|
/// Plan a plugin bundle whose files are governed by a delegated maintainer.
fn main raise {
  let root_key = @testkit.signer(242)
  let team_key = @testkit.signer(243)
  let hash = @crypto.sha256_hex(b"abc")
  let child_body = "{\"_type\":\"targets\",\"spec_version\":\"1.0.37\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{\"apps/a.bin\":{\"length\":3,\"hashes\":{\"sha256\":\"\{hash}\"}},\"apps/b.bin\":{\"length\":3,\"hashes\":{\"sha256\":\"\{hash}\"}}}}"
  let child = @testkit.signed_envelope(child_body, [team_key])
  let top = @testkit.top_with_delegation(
    1, "team", "apps/*.bin", root_key, team_key,
  )
  let snapshot = @testkit.snapshot_with_delegation(
    1, top, "team", child, root_key,
  )
  let timestamp = @testkit.timestamp(1, 1, snapshot, root_key)
  let client = @client.open_trusted_root(
      @testkit.root(1, root_key, [root_key], consistent_snapshot=true),
      "2026-10-20T00:00:00Z",
    )
    .unwrap()
    .accept_timestamp(timestamp)
    .unwrap()
    .accept_snapshot(snapshot)
    .unwrap()
    .accept_targets(top)
    .unwrap()
  let mut loads = 0
  let plan = client
    .resolve_plan(["apps/a.bin", "apps/b.bin"], fn(name) {
      loads += 1
      if name == "1.team.json" {
        Some(child)
      } else {
        None
      }
    })
    .unwrap()
  assert_eq(loads, 1)
  assert_eq(plan.targets().length(), 2)
  assert_eq(plan.metadata_loads(), 1)
  for item in plan.targets() {
    assert_eq(item.resolution().role_chain(), ["targets", "team"])
    assert_true(item.repository_name().has_prefix("apps/" + hash))
    println(item.resolution().descriptor().path() + " via targets -> team")
  }
  println(
    "Two delegated bundle files planned with one metadata fetch; bytes still require verification",
  )
}
