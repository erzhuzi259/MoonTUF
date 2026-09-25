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
test "delegation visit budget permits the exact single-role boundary" {
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

///|
// All roles in these graph fixtures have version 1 and distinct signing keys.
fn graph_targets(
  signer : @testkit.Signer,
  roles : Array[(String, @testkit.Signer, Bool)],
) -> Bytes {
  let keys : Array[String] = []
  let policies : Array[String] = []
  for entry in roles {
    let (name, key, terminating) = entry
    let keyid = key.keyid()
    let key_json = key.key_json()
    let terminal = if terminating { "true" } else { "false" }
    keys.push("\"\{keyid}\":\{key_json}")
    policies.push(
      "{\"name\":\"\{name}\",\"keyids\":[\"\{keyid}\"],\"threshold\":1,\"paths\":[\"apps/*.bin\"],\"terminating\":\{terminal}}",
    )
  }
  let signed = "{\"_type\":\"targets\",\"spec_version\":\"1.0.0\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{},\"delegations\":{\"keys\":{\{keys.join(",")}},\"roles\":[\{policies.join(",")}]}}"
  @testkit.signed_envelope(signed, [signer])
}

///|
fn graph_client(
  key : @testkit.Signer,
  top : Bytes,
  delegated : Array[(String, Bytes)],
  max_roles? : Int = 32,
) -> Client {
  let records = delegated.copy()
  records.push(("targets", top))
  let entries : Array[String] = []
  for record in records {
    let (name, raw) = record
    let length = raw.length()
    let digest = @crypto.sha256_hex(raw)
    entries.push(
      "\"\{name}.json\":{\"version\":1,\"length\":\{length},\"hashes\":{\"sha256\":\"\{digest}\"}}",
    )
  }
  let signed = "{\"_type\":\"snapshot\",\"spec_version\":\"1.0.0\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"meta\":{\{entries.join(",")}}}"
  let snapshot = @testkit.signed_envelope(signed, [key])
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  open_trusted_root(
    @testkit.root(1, key, [key], consistent_snapshot=true),
    "2026-09-25T00:00:00Z",
    budget=budgets(max_delegated_roles=max_roles),
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
test "delegations search descendants before later sibling roles" {
  let top_key = @testkit.signer(60)
  let first_key = @testkit.signer(61)
  let leaf_key = @testkit.signer(62)
  let sibling_key = @testkit.signer(63)
  let top = graph_targets(top_key, [
    ("first", first_key, false),
    ("sibling", sibling_key, false),
  ])
  let first = graph_targets(first_key, [("leaf", leaf_key, false)])
  let leaf = @testkit.targets(
    1,
    "apps/demo.bin",
    @utf8.encode("leaf"),
    leaf_key,
  )
  let sibling = @testkit.targets(
    1,
    "apps/demo.bin",
    @utf8.encode("sibling"),
    sibling_key,
  )
  let client = graph_client(top_key, top, [
    ("first", first),
    ("leaf", leaf),
    ("sibling", sibling),
  ])
  let requested : Array[String] = []
  let load = fn(name : String) -> Bytes? {
    requested.push(name)
    match name {
      "1.first.json" => Some(first)
      "1.leaf.json" => Some(leaf)
      "1.sibling.json" => Some(sibling)
      _ => None
    }
  }
  let resolved = client.find_target_detail("apps/demo.bin", load).unwrap()
  assert_eq(resolved.role_chain(), ["targets", "first", "leaf"])
  assert_eq(resolved.descriptor().length(), 4)
  assert_eq(requested, ["1.first.json", "1.leaf.json"])
}

///|
test "terminating delegation miss blocks a later matching sibling" {
  let top_key = @testkit.signer(64)
  let first_key = @testkit.signer(65)
  let sibling_key = @testkit.signer(66)
  let top = graph_targets(top_key, [
    ("first", first_key, true),
    ("sibling", sibling_key, false),
  ])
  let first = @testkit.empty_targets(1, first_key)
  let sibling = @testkit.targets(
    1,
    "apps/demo.bin",
    @utf8.encode("sibling"),
    sibling_key,
  )
  let client = graph_client(top_key, top, [
    ("first", first),
    ("sibling", sibling),
  ])
  let requested : Array[String] = []
  let load = fn(name : String) -> Bytes? {
    requested.push(name)
    match name {
      "1.first.json" => Some(first)
      "1.sibling.json" => Some(sibling)
      _ => None
    }
  }
  assert_true(
    client.find_target("apps/demo.bin", load)
    is Err(TargetNotFound("apps/demo.bin")),
  )
  assert_eq(requested, ["1.first.json"])
}

///|
test "nested terminating miss also blocks ancestor siblings" {
  let top_key = @testkit.signer(67)
  let first_key = @testkit.signer(68)
  let stop_key = @testkit.signer(69)
  let sibling_key = @testkit.signer(70)
  let top = graph_targets(top_key, [
    ("first", first_key, false),
    ("sibling", sibling_key, false),
  ])
  let first = graph_targets(first_key, [("stop", stop_key, true)])
  let stop = @testkit.empty_targets(1, stop_key)
  let sibling = @testkit.targets(
    1,
    "apps/demo.bin",
    @utf8.encode("sibling"),
    sibling_key,
  )
  let client = graph_client(top_key, top, [
    ("first", first),
    ("stop", stop),
    ("sibling", sibling),
  ])
  let requested : Array[String] = []
  let load = fn(name : String) -> Bytes? {
    requested.push(name)
    match name {
      "1.first.json" => Some(first)
      "1.stop.json" => Some(stop)
      "1.sibling.json" => Some(sibling)
      _ => None
    }
  }
  assert_true(
    client.find_target("apps/demo.bin", load)
    is Err(TargetNotFound("apps/demo.bin")),
  )
  assert_eq(requested, ["1.first.json", "1.stop.json"])
}

///|
test "delegation visit limit rejects the next role before fetching it" {
  let top_key = @testkit.signer(71)
  let first_key = @testkit.signer(72)
  let sibling_key = @testkit.signer(73)
  let top = graph_targets(top_key, [
    ("first", first_key, false),
    ("sibling", sibling_key, false),
  ])
  let first = @testkit.empty_targets(1, first_key)
  let sibling = @testkit.targets(
    1,
    "apps/demo.bin",
    @utf8.encode("sibling"),
    sibling_key,
  )
  let metadata = [("first", first), ("sibling", sibling)]
  let limited = graph_client(top_key, top, metadata, max_roles=1)
  let requested : Array[String] = []
  let load = fn(name : String) -> Bytes? {
    requested.push(name)
    match name {
      "1.first.json" => Some(first)
      "1.sibling.json" => Some(sibling)
      _ => None
    }
  }
  assert_true(
    limited.find_target("apps/demo.bin", load) is Err(DelegationLimit(1)),
  )
  assert_eq(requested, ["1.first.json"])
  let exact = graph_client(top_key, top, metadata, max_roles=2)
  let resolved = exact.find_target_detail("apps/demo.bin", load).unwrap()
  assert_eq(resolved.role_chain(), ["targets", "sibling"])
  assert_eq(resolved.descriptor().length(), 7)
  assert_eq(requested, ["1.first.json", "1.first.json", "1.sibling.json"])
}
