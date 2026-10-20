///|
fn shared_delegated_fixture() -> (@client.Client, Bytes) {
  let top_key = @testkit.signer(231)
  let child_key = @testkit.signer(232)
  let digest = @crypto.sha256_hex(b"abc")
  let body = "{\"_type\":\"targets\",\"spec_version\":\"1.0.37\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{\"apps/a.bin\":{\"length\":3,\"hashes\":{\"sha256\":\"\{digest}\"}},\"apps/b.bin\":{\"length\":3,\"hashes\":{\"sha256\":\"\{digest}\"}}}}"
  let child = @testkit.signed_envelope(body, [child_key])
  (delegated_chain(top_key, child_key, child), child)
}

///|
test "resolution plan preserves order caches shared delegation and returns role evidence" {
  let (client, child) = shared_delegated_fixture()
  let mut calls = 0
  let plan = client
    .resolve_plan(["apps/b.bin", "apps/a.bin"], fn(name) {
      calls += 1
      if name != "1.apps.json" {
        abort("unexpected request")
      }
      Some(child)
    })
    .unwrap()
  assert_eq(calls, 1)
  assert_eq(plan.metadata_loads(), 1)
  assert_eq(plan.targets()[0].resolution().descriptor().path(), "apps/b.bin")
  assert_eq(plan.targets()[1].resolution().role_chain(), ["targets", "apps"])
  assert_true(plan.targets()[0].repository_name().has_suffix(".b.bin"))
  assert_eq(plan.root_sha256().length(), 64)
  assert_eq(plan.snapshot_version(), 1)
  let detached = plan.targets()
  detached.clear()
  assert_eq(plan.targets().length(), 2)
}

///|
test "resolution validates entire request before loading and rejects incomplete plans" {
  let (client, child) = shared_delegated_fixture()
  let mut calls = 0
  let load = fn(_) {
    calls += 1
    Some(child)
  }
  assert_true(
    client.resolve_plan(["apps/a.bin", "apps/a.bin"], load)
    is Err(InvalidPath(_)),
  )
  assert_true(client.resolve_plan(["../bad"], load) is Err(InvalidPath(_)))
  assert_true(
    client.resolve_plan(["apps/a.bin"], load, max_targets=0)
    is Err(ResourceLimit(_, _, _)),
  )
  assert_eq(calls, 0)
  assert_true(
    client.resolve_plan(["apps/a.bin"], load, max_metadata=0)
    is Err(DelegationLimit(0)),
  )
  assert_eq(calls, 0)
  assert_true(
    client.resolve_plan(["apps/a.bin", "apps/missing.bin"], load)
    is Err(TargetNotFound(_)),
  )
  assert_eq(
    client.resolve_plan([], load, max_metadata=0).unwrap().targets().length(),
    0,
  )
}

///|
test "mirror fallback verifies exact pinned bytes and stops on success" {
  let client = complete_chain(@testkit.signer(233), "app.bin", b"abc")
  let names : Array[String] = []
  let outcome = client
    .download_from_mirrors(
      "app.bin",
      ["offline", "corrupt", "short", "healthy", "unused"],
      fn(_) { None },
      fn(mirror, name, maximum) {
        names.push(mirror)
        if maximum != 3L {
          abort("unexpected maximum")
        }
        if !name.has_suffix("app.bin") {
          abort("unexpected target")
        }
        match mirror {
          "offline" => None
          "corrupt" => Some(b"xyz")
          "short" => Some(b"ab")
          _ => Some(b"abc")
        }
      },
    )
    .unwrap()
  assert_eq(names, ["offline", "corrupt", "short", "healthy"])
  assert_eq(outcome.target().unwrap().bytes(), b"abc")
  assert_true(outcome.attempts()[0].status() is Unavailable)
  assert_true(outcome.attempts()[1].status() is Rejected(HashMismatch(_)))
  assert_true(
    outcome.attempts()[2].status() is Rejected(LengthMismatch(_, _, _)),
  )
  assert_true(outcome.attempts()[3].status() is Verified)
  assert_eq(outcome.attempts()[3].mirror(), "healthy")
  let detached = outcome.attempts()
  detached.clear()
  assert_eq(outcome.attempts().length(), 4)
}

///|
test "mirror failure and invalid requests never manufacture verified results" {
  let client = complete_chain(@testkit.signer(234), "app.bin", b"abc")
  let mut fetched = 0
  let fetch = fn(_, _, _) {
    fetched += 1
    Some(b"bad")
  }
  let load = fn(_) { None }
  assert_true(
    client.download_from_mirrors("app.bin", [], load, fetch)
    is Err(ResourceLimit(_, _, _)),
  )
  assert_true(
    client.download_from_mirrors("app.bin", ["m", "m"], load, fetch)
    is Err(InvalidPath(_)),
  )
  assert_true(
    client.download_from_mirrors("missing", ["m"], load, fetch)
    is Err(TargetNotFound(_)),
  )
  assert_eq(fetched, 0)
  let failed = client
    .download_from_mirrors("app.bin", ["a", "b"], load, fetch)
    .unwrap()
  assert_true(failed.target() is None)
  assert_eq(failed.attempts().length(), 2)
}

///|
test "local resumable state retains partial timestamp and rejects anchor and clock changes" {
  let key = @testkit.signer(235)
  let root = @testkit.root(1, key, [key])
  let targets = @testkit.targets(1, "app.bin", b"abc", key)
  let snapshot = @testkit.snapshot(1, 1, targets, key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  let partial = @client.open_trusted_root(root, "2026-10-20T00:00:00Z")
    .unwrap()
    .accept_timestamp(timestamp)
    .unwrap()
  let saved = partial.save_state()
  let restored = @client.restore_state(saved, root, "2026-10-21T00:00:00Z").unwrap()
  assert_false(restored.ready())
  assert_eq(restored.timestamp_version(), Some(1))
  assert_true(
    @client.restore_state(saved, root, "2026-10-19T00:00:00Z")
    is Err(ClockRollback(_, _)),
  )
  assert_true(
    @client.restore_state(
      saved,
      @testkit.root(2, key, [key]),
      "2026-10-21T00:00:00Z",
    )
    is Err(CheckpointRootMismatch),
  )
  let outcome = restored.refresh(fn(name) {
    match name {
      "2.root.json" => MetadataAbsent
      "timestamp.json" => MetadataPresent(timestamp)
      "snapshot.json" => MetadataPresent(snapshot)
      "targets.json" => MetadataPresent(targets)
      _ => MetadataFailure
    }
  })
  assert_true(outcome.status() is Complete)
  assert_eq(
    outcome
    .client()
    .verify_top_level_target("app.bin", b"abc")
    .unwrap()
    .length(),
    3L,
  )
}
