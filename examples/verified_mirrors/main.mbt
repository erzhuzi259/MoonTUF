///|
/// Public deterministic test keys, never production signing material.
fn main raise {
  let key = @testkit.signer(241)
  let root = @testkit.root(1, key, [key], consistent_snapshot=true)
  let targets = @testkit.targets(1, "models/rules.bin", b"valid-model", key)
  let snapshot = @testkit.snapshot(1, 1, targets, key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  let client = @client.open_trusted_root(root, "2026-10-20T00:00:00Z")
    .unwrap()
    .accept_timestamp(timestamp)
    .unwrap()
    .accept_snapshot(snapshot)
    .unwrap()
    .accept_targets(targets)
    .unwrap()
  let result = client
    .download_from_mirrors(
      "models/rules.bin",
      ["region-A", "region-B", "offline-cache"],
      fn(_) { None },
      fn(mirror, _, _) {
        match mirror {
          "region-A" => None
          "region-B" => Some(b"evil--model")
          _ => Some(b"valid-model")
        }
      },
    )
    .unwrap()
  assert_eq(result.attempts().length(), 3)
  assert_true(result.attempts()[0].status() is @client.Unavailable)
  assert_true(result.attempts()[1].status() is @client.Rejected(_))
  assert_eq(result.target().unwrap().bytes(), b"valid-model")
  println(
    "Unavailable and corrupt mirrors rejected; exact trusted bytes obtained from the cache",
  )
  let failed = client
    .download_from_mirrors("models/rules.bin", ["bad"], fn(_) { None }, fn(
      _,
      _,
      _,
    ) {
      Some(b"evil--model")
    })
    .unwrap()
  assert_true(failed.target() is None)
  println("All-invalid mirrors produce no verified target and no installation")
}
