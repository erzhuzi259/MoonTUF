///|
/// Deterministic synthetic signing material for tests and demos only.
/// Never use these seeded keys to authorize real updates.
pub struct Signer {
  secret : @ed25519.PrivateKey
  keyid : String
  key_json : String
}

///|
pub fn signer(seed_byte : Byte) -> Signer {
  let seed : Array[Byte] = []
  for _ in 0..<32 {
    seed.push(seed_byte)
  }
  let secret = @ed25519.PrivateKey::new(Bytes::from_array(seed)[:]) catch {
    _ => abort("test seed must be 32 bytes")
  }
  let public_hex = @crypto.encode_hex(secret.public().bytes())
  let key_json = "{\"keytype\":\"ed25519\",\"scheme\":\"ed25519\",\"keyval\":{\"public\":\"\{public_hex}\"}}"
  let parsed = @wire.parse(@utf8.encode(key_json)).unwrap()
  let keyid = @crypto.sha256_hex(@wire.canonical(parsed))
  { secret, keyid, key_json, }
}

///|
pub fn Signer::keyid(self : Signer) -> String {
  self.keyid
}

///|
pub fn Signer::key_json(self : Signer) -> String {
  self.key_json
}

///|
pub fn signed_envelope(signed_json : String, signers : Array[Signer]) -> Bytes {
  let value = @wire.parse(@utf8.encode(signed_json)).unwrap()
  let canonical = @wire.canonical(value)
  let entries : Array[String] = []
  for signer in signers {
    let signature = @crypto.encode_hex(signer.secret.sign(canonical[:]))
    entries.push("{\"keyid\":\"\{signer.keyid}\",\"sig\":\"\{signature}\"}")
  }
  @utf8.encode(
    "{\"signed\":\{signed_json},\"signatures\":[\{entries.join(",")}]}",
  )
}

///|
pub fn root(
  version : Int,
  authority : Signer,
  signers : Array[Signer],
  expires? : String = "2030-01-01T00:00:00Z",
  consistent_snapshot? : Bool = false,
) -> Bytes {
  let keyid = authority.keyid
  let key_json = authority.key_json
  let role = "{\"keyids\":[\"\{keyid}\"],\"threshold\":1}"
  let consistent = if consistent_snapshot { "true" } else { "false" }
  let signed_json = "{\"_type\":\"root\",\"spec_version\":\"1.0.0\",\"version\":\{version},\"expires\":\"\{expires}\",\"consistent_snapshot\":\{consistent},\"keys\":{\"\{keyid}\":\{key_json}},\"roles\":{\"root\":\{role},\"timestamp\":\{role},\"snapshot\":\{role},\"targets\":\{role}}}"
  signed_envelope(signed_json, signers)
}

///|
pub fn timestamp(
  version : Int,
  snapshot_version : Int,
  snapshot_raw : Bytes,
  signer : Signer,
  expires? : String = "2030-01-01T00:00:00Z",
) -> Bytes {
  let length = snapshot_raw.length()
  let digest = @crypto.sha256_hex(snapshot_raw)
  let signed_json = "{\"_type\":\"timestamp\",\"spec_version\":\"1.0.0\",\"version\":\{version},\"expires\":\"\{expires}\",\"meta\":{\"snapshot.json\":{\"version\":\{snapshot_version},\"length\":\{length},\"hashes\":{\"sha256\":\"\{digest}\"}}}}"
  signed_envelope(signed_json, [signer])
}

///|
pub fn snapshot(
  version : Int,
  targets_version : Int,
  targets_raw : Bytes,
  signer : Signer,
  expires? : String = "2030-01-01T00:00:00Z",
) -> Bytes {
  let length = targets_raw.length()
  let digest = @crypto.sha256_hex(targets_raw)
  let signed_json = "{\"_type\":\"snapshot\",\"spec_version\":\"1.0.0\",\"version\":\{version},\"expires\":\"\{expires}\",\"meta\":{\"targets.json\":{\"version\":\{targets_version},\"length\":\{length},\"hashes\":{\"sha256\":\"\{digest}\"}}}}"
  signed_envelope(signed_json, [signer])
}

///|
pub fn targets(
  version : Int,
  path : String,
  target_raw : Bytes,
  signer : Signer,
  expires? : String = "2030-01-01T00:00:00Z",
) -> Bytes {
  let length = target_raw.length()
  let digest = @crypto.sha256_hex(target_raw)
  let signed_json = "{\"_type\":\"targets\",\"spec_version\":\"1.0.0\",\"version\":\{version},\"expires\":\"\{expires}\",\"targets\":{\"\{path}\":{\"length\":\{length},\"hashes\":{\"sha256\":\"\{digest}\"}}}}"
  signed_envelope(signed_json, [signer])
}

///|
pub fn empty_targets(
  version : Int,
  signer : Signer,
  expires? : String = "2030-01-01T00:00:00Z",
) -> Bytes {
  let signed_json = "{\"_type\":\"targets\",\"spec_version\":\"1.0.0\",\"version\":\{version},\"expires\":\"\{expires}\",\"targets\":{}}"
  signed_envelope(signed_json, [signer])
}

///|
pub fn top_with_delegation(
  version : Int,
  role_name : String,
  pattern : String,
  top_signer : Signer,
  delegated_signer : Signer,
  terminating? : Bool = false,
) -> Bytes {
  let delegated_id = delegated_signer.keyid
  let delegated_key = delegated_signer.key_json
  let terminal = if terminating { "true" } else { "false" }
  let role = "{\"name\":\"\{role_name}\",\"keyids\":[\"\{delegated_id}\"],\"threshold\":1,\"paths\":[\"\{pattern}\"],\"terminating\":\{terminal}}"
  let signed_json = "{\"_type\":\"targets\",\"spec_version\":\"1.0.0\",\"version\":\{version},\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{},\"delegations\":{\"keys\":{\"\{delegated_id}\":\{delegated_key}},\"roles\":[\{role}]}}"
  signed_envelope(signed_json, [top_signer])
}

///|
pub fn snapshot_with_delegation(
  version : Int,
  top_targets : Bytes,
  delegated_role : String,
  delegated_targets : Bytes,
  signer : Signer,
  delegated_version? : Int = 1,
) -> Bytes {
  let top_length = top_targets.length()
  let top_hash = @crypto.sha256_hex(top_targets)
  let delegated_length = delegated_targets.length()
  let delegated_hash = @crypto.sha256_hex(delegated_targets)
  let signed_json = "{\"_type\":\"snapshot\",\"spec_version\":\"1.0.0\",\"version\":\{version},\"expires\":\"2030-01-01T00:00:00Z\",\"meta\":{\"targets.json\":{\"version\":1,\"length\":\{top_length},\"hashes\":{\"sha256\":\"\{top_hash}\"}},\"\{delegated_role}.json\":{\"version\":\{delegated_version},\"length\":\{delegated_length},\"hashes\":{\"sha256\":\"\{delegated_hash}\"}}}}"
  signed_envelope(signed_json, [signer])
}
