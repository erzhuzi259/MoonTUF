///|
fn signed_root_fixture() -> Bytes {
  let seed_array : Array[Byte] = []
  for index in 0..<32 { seed_array.push((index + 1).to_byte()) }
  let seed = Bytes::from_array(seed_array)
  let signer = @ed25519.PrivateKey::new(seed[:]) catch {
    _ => abort("invalid fixture seed")
  }
  let public_hex = @crypto.encode_hex(signer.public().bytes())
  let key_json =
    "{\"keytype\":\"ed25519\",\"scheme\":\"ed25519\",\"keyval\":{\"public\":\"\{public_hex}\"}}"
  let key = @wire.parse(@utf8.encode(key_json)).unwrap()
  let keyid = @crypto.sha256_hex(@wire.canonical(key))
  let role = "{\"keyids\":[\"\{keyid}\"],\"threshold\":1}"
  let signed_json =
    "{\"_type\":\"root\",\"spec_version\":\"1.0.0\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"keys\":{\"\{keyid}\":\{key_json}},\"roles\":{\"root\":\{role},\"timestamp\":\{role},\"snapshot\":\{role},\"targets\":\{role}}}"
  let signed_value = @wire.parse(@utf8.encode(signed_json)).unwrap()
  let canonical = @wire.canonical(signed_value)
  let sig = @crypto.encode_hex(signer.sign(canonical[:]))
  @utf8.encode(
    "{\"signed\":\{signed_json},\"signatures\":[{\"keyid\":\"\{keyid}\",\"sig\":\"\{sig}\"}]}",
  )
}

///|
test "real Ed25519 root signature passes its declared threshold" {
  let root = @model.parse_root(signed_root_fixture()).unwrap()
  assert_true(verify_root_self(root) is Ok(1))
}

///|
test "changing signed content after signing invalidates the root" {
  let raw = @utf8.decode(signed_root_fixture()) catch { _ => abort("invalid fixture") }
  let forged = raw.replace(old="\"version\":1", new="\"version\":2")
  let root = @model.parse_root(@utf8.encode(forged)).unwrap()
  assert_true(verify_root_self(root) is Err(ThresholdNotMet(_, _, _)))
}

///|
test "missing root signature does not bootstrap trust" {
  let raw = @utf8.decode(signed_root_fixture()) catch { _ => abort("invalid fixture") }
  let prefix = raw.split(",\"signatures\"").next().unwrap().to_owned()
  let unsigned = prefix + ",\"signatures\":[]}"
  let root = @model.parse_root(@utf8.encode(unsigned)).unwrap()
  assert_true(verify_root_self(root) is Err(ThresholdNotMet(_, _, _)))
}
