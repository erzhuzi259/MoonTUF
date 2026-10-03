///|
/// Demonstrate a host-supplied transport. The fixture keys below are public
/// test material and MUST NEVER authorize production updates.
fn metadata_loader(
  timestamp : Bytes,
  snapshot : Bytes,
  targets : Bytes,
) -> (String) -> Bytes? {
  fn(name : String) -> Bytes? {
    match name {
      "timestamp.json" => Some(timestamp)
      "snapshot.json" | "1.snapshot.json" => Some(snapshot)
      "targets.json" | "1.targets.json" => Some(targets)
      _ => None
    }
  }
}

///|
fn show_diagnostic(label : String, error : @client.ClientError) -> Unit {
  let message = @report.diagnose(error)
  println("[\{label}] rejected: \{message.to_json()}")
}

///|
fn run_single(
  label : String,
  prefix : String,
  path : String,
  content : String,
  seed : Byte,
) -> Unit {
  let key = @testkit.signer(seed)
  let bytes = @utf8.encode(content)
  let root = @testkit.root(1, key, [key], consistent_snapshot=true)
  let targets = @testkit.targets(1, path, bytes, key)
  let snapshot = @testkit.snapshot(1, 1, targets, key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  let load = metadata_loader(timestamp, snapshot, targets)
  let base = @client.open_trusted_root(root, "2026-09-25T00:00:00Z").unwrap()
  let refreshed = base.refresh(fn(name) {
    match load(name) {
      Some(bytes) => @client.MetadataPresent(bytes)
      None => @client.MetadataAbsent
    }
  })
  if !(refreshed.status() is @client.Complete) {
    abort("[\{label}] expected a complete metadata refresh")
  }
  let client = refreshed.client()
  let sync = client.plan_top_level_sync([], prefix~).unwrap()
  try! assert_eq(sync.missing().length(), 1)
  try! assert_eq(sync.missing()[0].path(), path)
  try! assert_eq(
    client
    .diff_top_level_inventory(client, prefix~, max_changes=0)
    .unwrap()
    .unchanged(),
    1,
  )
  println(
    "[\{label}] trusted inventory comparison and cache synchronization: ok",
  )
  let policy = @admission.policy(prefix~, max_bytes=4096L).unwrap()
  let decision = @admission.evaluate(client, path, policy, load).unwrap()
  match decision {
    @admission.Current =>
      abort("[\{label}] expected a download without an installed digest")
    @admission.Download(ticket) => {
      println("[\{label}] requested \{ticket.repository_name()}")
      let urls = @transport.repository_urls(
        "https://updates.example.invalid/metadata", "https://updates.example.invalid/targets",
      ).unwrap()
      let hint = urls.target_request(ticket).unwrap()
      hint
      .check_response(200, Some(bytes.length().to_int64()), "identity")
      .unwrap()
      let meter = hint.meter()
      meter.consume_bytes(bytes).unwrap()
      ignore(meter.finish().unwrap())
      println("[\{label}] bounded fetch URL: \{hint.url()}")
      let verified = @admission.verify_download(client, ticket, bytes, load).unwrap()
      println(
        "[\{label}] verified \{verified.path()}, bytes=\{verified.length()}, sha256=\{verified.sha256()}",
      )
    }
  }
  let installed = @admission.evaluate(
    client,
    path,
    policy,
    load,
    installed_sha256=@crypto.sha256_hex(bytes),
  ).unwrap()
  if installed is @admission.Current {
    println("[\{label}] installed digest matches trusted target")
  } else {
    abort("[\{label}] matching installed digest was not recognized")
  }
  let bad = @utf8.encode(content + " tampered")
  match client.verify_target(path, bad, load) {
    Err(error) => show_diagnostic(label, error)
    Ok(_) => abort("[\{label}] tampering was accepted")
  }
}

///|
/// One metadata snapshot can authorize a bundle of independent targets. The
/// host must stage all files and commit them atomically after verification.
fn run_bundle() -> Unit {
  let key = @testkit.signer(90)
  let core = @utf8.encode("plugin-core-v1")
  let data = @utf8.encode("plugin-data-v1")
  let core_hash = @crypto.sha256_hex(core)
  let data_hash = @crypto.sha256_hex(data)
  let signed = "{\"_type\":\"targets\",\"spec_version\":\"1.0.0\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{\"plugins/core.bin\":{\"length\":\{core.length()},\"hashes\":{\"sha256\":\"\{core_hash}\"}},\"plugins/data.bin\":{\"length\":\{data.length()},\"hashes\":{\"sha256\":\"\{data_hash}\"}}}}"
  let targets = @testkit.signed_envelope(signed, [key])
  let snapshot = @testkit.snapshot(1, 1, targets, key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  let load = metadata_loader(timestamp, snapshot, targets)
  let refreshed = @client.open_trusted_root(
      @testkit.root(1, key, [key]),
      "2026-09-25T00:00:00Z",
    )
    .unwrap()
    .refresh(fn(name) {
      match load(name) {
        Some(bytes) => @client.MetadataPresent(bytes)
        None => @client.MetadataAbsent
      }
    })
  if !(refreshed.status() is @client.Complete) {
    abort("[bundle] expected a complete metadata refresh")
  }
  let client = refreshed.client()
  let policy = @admission.bundle_policy(
    @admission.policy(prefix="plugins", max_bytes=4096L).unwrap(),
    max_files=2,
    max_total_bytes=8192L,
  ).unwrap()
  let plan = @admission.plan_bundle(
    client,
    ["plugins/core.bin", "plugins/data.bin"],
    policy,
    load,
  ).unwrap()
  if plan.tickets().length() != 2 {
    abort("[bundle] expected exactly two download tickets")
  }
  println(
    "[bundle] planned \{plan.tickets().length()} files, \{plan.total_bytes()} bytes",
  )
  let session = @admission.open_bundle_session(client, plan, load).unwrap()
  session.write_file(0, core).unwrap()
  session.finish_file(0).unwrap()
  session.write_file(1, data).unwrap()
  session.finish_file(1).unwrap()
  let verified = session.finish_bundle().unwrap()
  if verified.length() != 2 {
    abort("[bundle] expected exactly two verified receipts")
  }
  println("[bundle] all \{verified.length()} files verified before commit")
}

///|
fn main {
  println("MoonTUF offline host integration demo; fixture keys only")
  run_single("app", "apps", "apps/client.bin", "app-v1", 81)
  run_single("plugin", "plugins", "plugins/sample.wasm", "plugin-v1", 82)
  run_single("firmware", "firmware", "firmware/router.img", "firmware-v1", 83)
  run_single("model", "models", "models/weights.bin", "model-v1", 84)
  run_single("rules", "rules", "rules/policy.dat", "rules-v1", 85)
  run_bundle()
}
