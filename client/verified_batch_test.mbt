///|
test "verified batch is all-or-error and budgeted before any delegated load" {
  let c = complete_chain(@testkit.signer(250), "a.bin", b"abc")
  let batch = c.verify_batch([("a.bin", b"abc")], _ => None).unwrap()
  assert_eq(batch.length(), 3L)
  assert_eq(batch.targets()[0].bytes(), b"abc")
  assert_eq(batch.snapshot_version(), 1)
  assert_eq(batch.root_sha256().length(), 64)
  assert_true(
    c.verify_batch([("a.bin", b"abd")], _ => None) is Err(HashMismatch(_)),
  )
  assert_true(
    c.verify_batch([("a.bin", b"abc"), ("a.bin", b"abc")], _ => None)
    is Err(InvalidPath(_)),
  )
  let mut loads = 0
  assert_true(
    c.verify_batch(
      [("a.bin", b"abc")],
      _ => {
        loads += 1
        None
      },
      max_total_bytes=2L,
    )
    is Err(TargetResourceLimit(_, _, _)),
  )
  assert_eq(loads, 0)
  let detached = batch.targets()
  detached.clear()
  assert_eq(batch.targets().length(), 1)
}

///|
test "expiry horizon reports inclusive expiry without advancing trust time" {
  let c = complete_chain(@testkit.signer(251), "a.bin", b"abc")
  let early = c.expiry_horizon("2029-12-31T23:59:59Z").unwrap()
  assert_eq(early.length(), 4)
  assert_false(early.any(r => r.due()))
  let exact = c.expiry_horizon("2030-01-01T00:00:00Z").unwrap()
  assert_true(exact.all(r => r.due()))
  assert_eq(c.update_start(), "2026-09-25T00:00:00Z")
  assert_true(c.verify_batch([("a.bin", b"abc")], _ => None) is Ok(_))
  assert_true(c.expiry_horizon("bad") is Err(InvalidStartTime(_)))
  assert_true(
    c.expiry_horizon("2026-01-01T00:00:00Z") is Err(ClockRollback(_, _)),
  )
  let expired = c.begin_update("2030-01-01T00:00:00Z").unwrap()
  assert_true(expired.verify_batch([], _ => None) is Err(Expired(_)))
}

///|
test "batch verifies all delegated artifacts in caller order with a shared metadata fetch" {
  let (client, child) = shared_delegated_fixture()
  let mut loads = 0
  let load = fn(name) {
    loads += 1
    if name != "1.apps.json" {
      abort("unexpected delegated metadata name")
    }
    Some(child)
  }
  let verified = client
    .verify_batch(
      [("apps/b.bin", b"abc"), ("apps/a.bin", b"abc")],
      load,
      max_total_bytes=6L,
    )
    .unwrap()
  assert_eq(loads, 1)
  assert_eq(verified.length(), 6L)
  assert_eq(verified.targets().map(t => t.path()), ["apps/b.bin", "apps/a.bin"])
  // A valid first item must not escape when the second item's bytes are corrupt.
  assert_true(
    client.verify_batch([("apps/a.bin", b"abc"), ("apps/b.bin", b"bad")], load)
    is Err(HashMismatch(_)),
  )
  let before = loads
  assert_true(
    client.verify_batch(
      [("apps/a.bin", b"abc"), ("apps/b.bin", b"abc")],
      load,
      max_total_bytes=5L,
    )
    is Err(TargetResourceLimit(_, _, _)),
  )
  assert_eq(loads, before)
}
