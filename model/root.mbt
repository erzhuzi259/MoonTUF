///|
pub struct PublicKey {
  keyid : String
  public_hex : String
}

///|
pub fn PublicKey::keyid(self : PublicKey) -> String { self.keyid }

///|
pub fn PublicKey::public_hex(self : PublicKey) -> String { self.public_hex }

///|
pub struct RoleKeys {
  keyids : Array[String]
  threshold : Int
}

///|
pub fn RoleKeys::keyids(self : RoleKeys) -> Array[String] { self.keyids }

///|
pub fn RoleKeys::threshold(self : RoleKeys) -> Int { self.threshold }

///|
pub struct Root {
  envelope : Envelope
  common : Common
  consistent_snapshot : Bool
  keys : Array[PublicKey]
  roles : Array[(String, RoleKeys)]
}

///|
pub fn Root::envelope(self : Root) -> Envelope { self.envelope }

///|
pub fn Root::common(self : Root) -> Common { self.common }

///|
pub fn Root::consistent_snapshot(self : Root) -> Bool { self.consistent_snapshot }

///|
pub fn Root::keys(self : Root) -> Array[PublicKey] { self.keys }

///|
pub fn Root::role(self : Root, name : String) -> RoleKeys? {
  for entry in self.roles {
    let (candidate, role) = entry
    if candidate == name { return Some(role) }
  }
  None
}

///|
pub fn Root::key(self : Root, keyid : String) -> PublicKey? {
  for key in self.keys {
    if key.keyid == keyid { return Some(key) }
  }
  None
}

///|
fn read_key(keyid : String, raw : @wire.Value) -> Result[PublicKey, ModelError] {
  ignore(match object(raw, "signed.keys." + keyid) {
    Ok(value) => value
    Err(error) => return Err(error)
  })
  let keytype = match text_field(raw, "keytype", "signed.keys." + keyid) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let scheme = match text_field(raw, "scheme", "signed.keys." + keyid) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  if keytype != "ed25519" || scheme != "ed25519" {
    return Err(InvalidValue("signed.keys." + keyid, "unsupported key type or scheme"))
  }
  let keyval = match field(raw, "keyval", "signed.keys." + keyid) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let public_hex = match text_field(keyval, "public", "signed.keys." + keyid + ".keyval") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let decoded = match @crypto.decode_hex(public_hex) {
    Ok(value) => value
    Err(_) => return Err(InvalidValue("signed.keys." + keyid + ".keyval.public", "invalid hex"))
  }
  if decoded.length() != 32 {
    return Err(InvalidValue("signed.keys." + keyid + ".keyval.public", "Ed25519 key must have 32 bytes"))
  }
  let calculated = @crypto.sha256_hex(@wire.canonical(raw))
  if calculated != keyid {
    return Err(InvalidKeyId(keyid))
  }
  Ok({ keyid, public_hex })
}

///|
fn read_role(name : String, raw : @wire.Value, keys : Array[PublicKey]) -> Result[RoleKeys, ModelError] {
  ignore(match object(raw, "signed.roles." + name) {
    Ok(value) => value
    Err(error) => return Err(error)
  })
  let ids_value = match field(raw, "keyids", "signed.roles." + name) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let ids = match array(ids_value, "signed.roles." + name + ".keyids") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let keyids : Array[String] = []
  for item in ids {
    let id = match string(item, "signed.roles." + name + ".keyids[]") {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    if keyids.contains(id) {
      return Err(DuplicateItem("signed.roles." + name + ".keyids=" + id))
    }
    let mut found = false
    for key in keys {
      if key.keyid == id { found = true; break }
    }
    if !found {
      return Err(InvalidValue("signed.roles." + name, "missing declared key " + id))
    }
    keyids.push(id)
  }
  let threshold = match positive_field(raw, "threshold", "signed.roles." + name) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  if threshold > keyids.length() {
    return Err(InvalidValue("signed.roles." + name + ".threshold", "larger than distinct key count"))
  }
  Ok({ keyids, threshold })
}

///|
/// Parse a root document but do not trust it yet. The client must verify its
/// signatures against an existing anchor (and, during rotation, against the
/// candidate root itself) before committing it.
pub fn parse_root(raw : Bytes, limits? : @wire.Limits = @wire.limits()) -> Result[Root, ModelError] {
  let envelope = match parse_envelope(raw, limits~) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let signed = envelope.signed()
  let common = match parse_common(signed, "root") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let consistent_snapshot = match signed.field("consistent_snapshot") {
    None => false
    Some(value) =>
      match value.as_boolean() {
        Some(flag) => flag
        None => return Err(WrongType("signed.consistent_snapshot"))
      }
  }
  let raw_keys = match field(signed, "keys", "signed") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let key_entries = match object(raw_keys, "signed.keys") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let keys : Array[PublicKey] = []
  for entry in key_entries {
    let (keyid, raw_key) = entry
    let key = match read_key(keyid, raw_key) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    keys.push(key)
  }
  let raw_roles = match field(signed, "roles", "signed") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let role_entries = match object(raw_roles, "signed.roles") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let roles : Array[(String, RoleKeys)] = []
  for entry in role_entries {
    let (name, raw_role) = entry
    let role = match read_role(name, raw_role, keys) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    roles.push((name, role))
  }
  for required in ["root", "timestamp", "snapshot", "targets"] {
    let mut present = false
    for entry in roles {
      let (name, _) = entry
      if name == required { present = true; break }
    }
    if !present { return Err(MissingField("signed.roles." + required)) }
  }
  Ok({ envelope, common, consistent_snapshot, keys, roles })
}
