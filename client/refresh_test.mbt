///|
test "one-shot refresh composes four-role verification" {
  let key = @testkit.signer(26)
  let artifact = @utf8.encode("abc")
  let targets = @testkit.targets(1, "apps/demo.bin", artifact, key)
  let snapshot = @testkit.snapshot(1, 1, targets, key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  let client = open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  let load = fn(name : String) -> Bytes? {
    match name {
      "timestamp.json" => Some(timestamp)
      "snapshot.json" => Some(snapshot)
      "targets.json" => Some(targets)
      _ => None
    }
  }
  let outcome = client.refresh(load)
  assert_true(outcome.status() is Complete)
  assert_true(outcome.client().ready())
  assert_eq(outcome.accepted().length(), 3)
  assert_eq(outcome.accepted()[0].name(), "timestamp.json")
  assert_eq(outcome.accepted()[1].name(), "snapshot.json")
  assert_eq(outcome.accepted()[2].name(), "targets.json")
}

///|
test "refresh returns partial trusted state after later fetch failure" {
  let key = @testkit.signer(27)
  let snapshot = @testkit.snapshot(1, 1, @testkit.empty_targets(1, key), key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  let client = open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  let load = fn(name : String) -> Bytes? {
    if name == "timestamp.json" {
      Some(timestamp)
    } else {
      None
    }
  }
  let outcome = client.refresh(load)
  assert_true(outcome.status() is Failed(MetadataUnavailable("snapshot.json")))
  assert_eq(outcome.client().timestamp_version(), Some(1))
  assert_eq(outcome.client().snapshot_version(), None)
  assert_eq(outcome.accepted().length(), 1)
  let recovered = outcome
    .client()
    .refresh(fn(name) {
      match name {
        "timestamp.json" => Some(timestamp)
        "snapshot.json" => Some(snapshot)
        "targets.json" => Some(@testkit.empty_targets(1, key))
        _ => None
      }
    })
  assert_true(recovered.status() is Complete)
  assert_true(recovered.client().ready())
  assert_eq(recovered.accepted().length(), 2)
  assert_eq(recovered.accepted()[0].name(), "snapshot.json")
  assert_eq(recovered.accepted()[1].name(), "targets.json")
}

///|
test "refresh resumes missing targets without fetching a retained snapshot" {
  let key = @testkit.signer(57)
  let targets = @testkit.empty_targets(1, key)
  let snapshot = @testkit.snapshot(1, 1, targets, key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  let initial = open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  let interrupted = initial.refresh(fn(name) {
    match name {
      "timestamp.json" => Some(timestamp)
      "snapshot.json" => Some(snapshot)
      _ => None
    }
  })
  assert_true(
    interrupted.status() is Failed(MetadataUnavailable("targets.json")),
  )
  let recovered = interrupted
    .client()
    .refresh(fn(name) {
      match name {
        "timestamp.json" => Some(timestamp)
        "targets.json" => Some(targets)
        "snapshot.json" => abort("retained snapshot should be reused")
        _ => None
      }
    })
  assert_true(recovered.status() is Complete)
  assert_true(recovered.client().ready())
  assert_eq(recovered.accepted().length(), 1)
  assert_eq(recovered.accepted()[0].name(), "targets.json")
}

///|
test "resuming an equal timestamp preserves the original snapshot pin" {
  let key = @testkit.signer(58)
  let targets = @testkit.empty_targets(1, key)
  let snapshot = @testkit.snapshot(1, 1, targets, key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  let partial = open_trusted_root(
      @testkit.root(1, key, [key]),
      "2026-09-25T00:00:00Z",
    )
    .unwrap()
    .accept_timestamp(timestamp)
    .unwrap()
  let replacement_snapshot = @testkit.snapshot(2, 1, targets, key)
  let replacement_timestamp = @testkit.timestamp(
    1, 2, replacement_snapshot, key,
  )
  let recovered = partial.refresh(fn(name) {
    match name {
      "timestamp.json" => Some(replacement_timestamp)
      "snapshot.json" => Some(snapshot)
      "targets.json" => Some(targets)
      _ => None
    }
  })
  assert_true(recovered.status() is Complete)
  assert_true(recovered.client().ready())
  assert_eq(recovered.client().snapshot_version(), Some(1))
  assert_eq(recovered.accepted().length(), 2)
}

///|
test "incomplete retries cannot revive expired retained metadata" {
  let key = @testkit.signer(59)
  let targets = @testkit.empty_targets(1, key)
  let snapshot = @testkit.snapshot(
    1,
    1,
    targets,
    key,
    expires="2026-09-26T00:00:00Z",
  )
  let expired_timestamp = @testkit.timestamp(
    1,
    1,
    snapshot,
    key,
    expires="2026-09-26T00:00:00Z",
  )
  let fresh_timestamp = @testkit.timestamp(1, 1, snapshot, key)
  let initial = open_trusted_root(
    @testkit.root(1, key, [key]),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  let load = fn(name : String) -> Bytes? {
    match name {
      "timestamp.json" => Some(fresh_timestamp)
      "snapshot.json" | "targets.json" =>
        abort("expired state must fail before loading descendants")
      _ => None
    }
  }
  let stale_timestamp = initial
    .accept_timestamp(expired_timestamp)
    .unwrap()
    .begin_update("2026-09-27T00:00:00Z")
    .unwrap()
    .refresh(load)
  assert_true(stale_timestamp.status() is Failed(Expired("timestamp")))
  let stale_snapshot = initial
    .accept_timestamp(fresh_timestamp)
    .unwrap()
    .accept_snapshot(snapshot)
    .unwrap()
    .begin_update("2026-09-27T00:00:00Z")
    .unwrap()
    .refresh(load)
  assert_true(stale_snapshot.status() is Failed(Expired("snapshot")))
}

///|
test "refresh can rotate root then validate metadata with new key" {
  let old_key = @testkit.signer(28)
  let new_key = @testkit.signer(29)
  let new_root = @testkit.root(2, new_key, [old_key, new_key])
  let targets = @testkit.empty_targets(1, new_key)
  let snapshot = @testkit.snapshot(1, 1, targets, new_key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, new_key)
  let client = open_trusted_root(
    @testkit.root(1, old_key, [old_key]),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  let load = fn(name : String) -> Bytes? {
    match name {
      "2.root.json" => Some(new_root)
      "timestamp.json" => Some(timestamp)
      "snapshot.json" => Some(snapshot)
      "targets.json" => Some(targets)
      _ => None
    }
  }
  let outcome = client.refresh(load)
  assert_true(outcome.status() is Complete)
  assert_eq(outcome.client().root_version(), 2)
  assert_eq(outcome.accepted().length(), 4)
  assert_eq(outcome.accepted()[0].name(), "2.root.json")
}

///|
test "refresh reports versioned repository names for consistent snapshots" {
  let key = @testkit.signer(56)
  let targets = @testkit.empty_targets(3, key)
  let snapshot = @testkit.snapshot(7, 3, targets, key)
  let timestamp = @testkit.timestamp(9, 7, snapshot, key)
  let client = open_trusted_root(
    @testkit.root(1, key, [key], consistent_snapshot=true),
    "2026-09-25T00:00:00Z",
  ).unwrap()
  let load = fn(name : String) -> Bytes? {
    match name {
      "timestamp.json" => Some(timestamp)
      "7.snapshot.json" => Some(snapshot)
      "3.targets.json" => Some(targets)
      _ => None
    }
  }
  let outcome = client.refresh(load)
  assert_true(outcome.status() is Complete)
  assert_eq(outcome.accepted().length(), 3)
  assert_eq(outcome.accepted()[0].name(), "timestamp.json")
  assert_eq(outcome.accepted()[1].name(), "7.snapshot.json")
  assert_eq(outcome.accepted()[2].name(), "3.targets.json")
}

///|
test "unchanged timestamp cannot conceal stale retained snapshot" {
  let key = @testkit.signer(49)
  let targets = @testkit.empty_targets(1, key)
  let snapshot = @testkit.snapshot(
    1,
    1,
    targets,
    key,
    expires="2026-09-26T00:00:00Z",
  )
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  let load = fn(name : String) -> Bytes? {
    match name {
      "timestamp.json" => Some(timestamp)
      "snapshot.json" => Some(snapshot)
      "targets.json" => Some(targets)
      _ => None
    }
  }
  let initial = open_trusted_root(
      @testkit.root(1, key, [key]),
      "2026-09-25T00:00:00Z",
    )
    .unwrap()
    .refresh(load)
    .client()
  assert_true(initial.ready())
  let next = initial.begin_update("2026-09-27T00:00:00Z").unwrap()
  assert_false(next.ready())
  assert_true(next.check_complete_fresh() is Err(Expired("snapshot")))
  let outcome = next.refresh(load)
  assert_true(outcome.status() is Failed(Expired("snapshot")))
}
