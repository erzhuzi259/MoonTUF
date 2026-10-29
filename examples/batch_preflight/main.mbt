///|
fn main raise {
  let key = @testkit.signer(252)
  let targets = @testkit.targets(1, "apps/update.bin", b"abc", key)
  let snapshot = @testkit.snapshot(1, 1, targets, key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  let c = @client.open_trusted_root(
      @testkit.root(1, key, [key]),
      "2026-10-29T00:00:00Z",
    )
    .unwrap()
    .accept_timestamp(timestamp)
    .unwrap()
    .accept_snapshot(snapshot)
    .unwrap()
    .accept_targets(targets)
    .unwrap()
  assert_eq(
    c
    .verify_batch([("apps/update.bin", b"abc")], _ => None, max_total_bytes=3L)
    .unwrap()
    .length(),
    3L,
  )
  assert_true(
    c.expiry_horizon("2030-01-01T00:00:00Z").unwrap().all(r => r.due()),
  )
  assert_eq(c.update_start(), "2026-10-29T00:00:00Z")
  println(
    "An explicit artifact batch verifies atomically; top-level expiry preflight schedules refresh without extending trust",
  )
}
