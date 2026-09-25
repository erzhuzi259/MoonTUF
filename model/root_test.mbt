///|
fn root_fixture(threshold : Int, omit_targets? : Bool = false) -> Bytes {
  let public_hex =
    "0000000000000000000000000000000000000000000000000000000000000000"
  let key_json =
    "{\"keytype\":\"ed25519\",\"scheme\":\"ed25519\",\"keyval\":{\"public\":\"\{public_hex}\"}}"
  let parsed_key = @wire.parse(@utf8.encode(key_json)).unwrap()
  let keyid = @crypto.sha256_hex(@wire.canonical(parsed_key))
  let role = "{\"keyids\":[\"\{keyid}\"],\"threshold\":\{threshold}}"
  let targets = if omit_targets { "" } else { ",\"targets\":\{role}" }
  @utf8.encode(
    "{\"signed\":{\"_type\":\"root\",\"spec_version\":\"1.0.0\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"consistent_snapshot\":true,\"keys\":{\"\{keyid}\":\{key_json}},\"roles\":{\"root\":\{role},\"timestamp\":\{role},\"snapshot\":\{role}\{targets}}},\"signatures\":[]}",
  )
}

///|
test "root parser validates keys, thresholds and top-level roles" {
  let root = parse_root(root_fixture(1)).unwrap()
  assert_eq(root.common().version(), 1)
  assert_true(root.consistent_snapshot())
  assert_eq(root.keys().length(), 1)
  assert_eq(root.role("targets").unwrap().threshold(), 1)
}

///|
test "root parser rejects unattainable threshold" {
  assert_true(parse_root(root_fixture(2)) is Err(InvalidValue(_, _)))
}

///|
test "root parser requires every top-level role" {
  assert_true(parse_root(root_fixture(1, omit_targets=true)) is Err(MissingField(_)))
}

///|
test "root parser rejects a forged key identifier" {
  let raw = root_fixture(1)
  let text = @utf8.decode(raw) catch { _ => abort("invalid fixture") }
  let forged = text.replace(old="0000000000000000000000000000000000000000000000000000000000000000", new="1111111111111111111111111111111111111111111111111111111111111111")
  assert_true(parse_root(@utf8.encode(forged)) is Err(InvalidKeyId(_)))
}
