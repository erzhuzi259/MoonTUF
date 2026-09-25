///|
/// A target descriptor binds one relative target path to exact bytes.
pub struct TargetFile {
  path : String
  length : Int
  sha256 : String
  custom : @wire.Value?
}

///|
pub fn TargetFile::path(self : TargetFile) -> String { self.path }

///|
pub fn TargetFile::length(self : TargetFile) -> Int { self.length }

///|
pub fn TargetFile::sha256(self : TargetFile) -> String { self.sha256 }

///|
pub fn TargetFile::custom(self : TargetFile) -> @wire.Value? { self.custom }

///|
pub fn safe_target_path(path : String) -> Bool {
  let bytes = @utf8.encode(path)
  if bytes.length() == 0 || bytes.length() > 4096 { return false }
  if bytes[0].to_int() == 47 || bytes[0].to_int() == 92 { return false }
  if path.contains("\\") || path.contains(":") { return false }
  let segments : Array[String] = path.split("/").map(part => part.to_owned()).collect()
  for segment in segments {
    if segment == "" || segment == "." || segment == ".." { return false }
  }
  for byte in bytes {
    let ch = byte.to_int()
    if ch < 32 || ch == 127 { return false }
  }
  true
}

///|
fn target_file(path : String, raw : @wire.Value) -> Result[TargetFile, ModelError] {
  if !safe_target_path(path) {
    return Err(InvalidValue("signed.targets." + path, "unsafe target path"))
  }
  ignore(match object(raw, "signed.targets." + path) {
    Ok(entries) => entries
    Err(error) => return Err(error)
  })
  let length = match nonnegative_field(raw, "length", "signed.targets." + path) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let sha256 = match sha256_field(raw, "signed.targets." + path) {
    Ok(Some(value)) => value
    Ok(None) => return Err(MissingField("signed.targets." + path + ".hashes.sha256"))
    Err(error) => return Err(error)
  }
  let custom = match raw.field("custom") {
    None => None
    Some(value) =>
      match value.as_dict() {
        Some(_) => Some(value)
        None => return Err(WrongType("signed.targets." + path + ".custom"))
      }
  }
  Ok({ path, length, sha256, custom })
}

///|
pub struct DelegatedRole {
  name : String
  keyids : Array[String]
  threshold : Int
  paths : Array[String]?
  path_hash_prefixes : Array[String]?
  terminating : Bool
}

///|
pub fn DelegatedRole::name(self : DelegatedRole) -> String { self.name }

///|
pub fn DelegatedRole::keyids(self : DelegatedRole) -> Array[String] { self.keyids }

///|
pub fn DelegatedRole::threshold(self : DelegatedRole) -> Int { self.threshold }

///|
pub fn DelegatedRole::paths(self : DelegatedRole) -> Array[String]? { self.paths }

///|
pub fn DelegatedRole::path_hash_prefixes(self : DelegatedRole) -> Array[String]? {
  self.path_hash_prefixes
}

///|
pub fn DelegatedRole::terminating(self : DelegatedRole) -> Bool { self.terminating }

///|
pub struct Delegations {
  keys : Array[PublicKey]
  roles : Array[DelegatedRole]
}

///|
pub fn Delegations::keys(self : Delegations) -> Array[PublicKey] { self.keys }

///|
pub fn Delegations::roles(self : Delegations) -> Array[DelegatedRole] { self.roles }

///|
pub fn Delegations::key(self : Delegations, keyid : String) -> PublicKey? {
  for key in self.keys {
    if key.keyid() == keyid { return Some(key) }
  }
  None
}

///|
fn string_list(raw : @wire.Value, path : String) -> Result[Array[String], ModelError] {
  let values = match array(raw, path) {
    Ok(items) => items
    Err(error) => return Err(error)
  }
  let items : Array[String] = []
  for value in values {
    let text = match string(value, path + "[]") {
      Ok(item) => item
      Err(error) => return Err(error)
    }
    items.push(text)
  }
  Ok(items)
}

///|
fn delegated_role(raw : @wire.Value, keys : Array[PublicKey]) -> Result[DelegatedRole, ModelError] {
  ignore(match object(raw, "signed.delegations.roles[]") {
    Ok(value) => value
    Err(error) => return Err(error)
  })
  let parent = "signed.delegations.roles[]"
  let name = match text_field(raw, "name", parent) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  if !safe_target_path(name) || name.has_suffix(".json") {
    return Err(InvalidValue(parent + ".name", "unsafe or reserved role name"))
  }
  let role_keys = match read_role(name, raw, keys) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let paths = match raw.field("paths") {
    None => None
    Some(value) =>
      match string_list(value, parent + ".paths") {
        Ok(items) => Some(items)
        Err(error) => return Err(error)
      }
  }
  let prefixes = match raw.field("path_hash_prefixes") {
    None => None
    Some(value) =>
      match string_list(value, parent + ".path_hash_prefixes") {
        Ok(items) => Some(items)
        Err(error) => return Err(error)
      }
  }
  if (paths is Some(_)) == (prefixes is Some(_)) {
    return Err(InvalidValue(parent, "exactly one of paths or path_hash_prefixes is required"))
  }
  if paths is Some(items) {
    for item in items {
      if item == "" || item.contains("\\") || item.contains("..") {
        return Err(InvalidValue(parent + ".paths", "unsafe path pattern"))
      }
    }
  }
  if prefixes is Some(items) {
    for item in items {
      if item.length() == 0 || item.length() > 64 {
        return Err(InvalidValue(parent + ".path_hash_prefixes", "invalid prefix length"))
      }
      for byte in @utf8.encode(item) {
        let ch = byte.to_int()
        if !((ch >= 48 && ch <= 57) || (ch >= 97 && ch <= 102)) {
          return Err(InvalidValue(parent + ".path_hash_prefixes", "prefix must be lowercase hex"))
        }
      }
    }
  }
  let terminating = match raw.field("terminating") {
    None => false
    Some(value) =>
      match value.as_boolean() {
        Some(flag) => flag
        None => return Err(WrongType(parent + ".terminating"))
      }
  }
  Ok({
    name,
    keyids: role_keys.keyids(),
    threshold: role_keys.threshold(),
    paths,
    path_hash_prefixes: prefixes,
    terminating,
  })
}

///|
fn parse_delegations(raw : @wire.Value) -> Result[Delegations, ModelError] {
  ignore(match object(raw, "signed.delegations") {
    Ok(value) => value
    Err(error) => return Err(error)
  })
  if raw.field("succinct_roles") is Some(_) {
    return Err(InvalidValue("signed.delegations.succinct_roles", "not supported by this profile"))
  }
  let key_values = match field(raw, "keys", "signed.delegations") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let key_entries = match object(key_values, "signed.delegations.keys") {
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
  let role_values = match field(raw, "roles", "signed.delegations") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let role_items = match array(role_values, "signed.delegations.roles") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let roles : Array[DelegatedRole] = []
  let names : Array[String] = []
  for raw_role in role_items {
    let role = match delegated_role(raw_role, keys) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    if names.contains(role.name()) {
      return Err(DuplicateItem("signed.delegations.roles[].name=" + role.name()))
    }
    names.push(role.name())
    roles.push(role)
  }
  Ok({ keys, roles })
}

///|
pub struct Targets {
  envelope : Envelope
  common : Common
  targets : Array[TargetFile]
  delegations : Delegations?
}

///|
pub fn Targets::envelope(self : Targets) -> Envelope { self.envelope }

///|
pub fn Targets::common(self : Targets) -> Common { self.common }

///|
pub fn Targets::targets(self : Targets) -> Array[TargetFile] { self.targets }

///|
pub fn Targets::delegations(self : Targets) -> Delegations? { self.delegations }

///|
pub fn Targets::target(self : Targets, path : String) -> TargetFile? {
  for target in self.targets {
    if target.path() == path { return Some(target) }
  }
  None
}

///|
pub fn parse_targets(raw : Bytes, limits? : @wire.Limits = @wire.limits()) -> Result[Targets, ModelError] {
  let envelope = match parse_envelope(raw, limits~) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let signed = envelope.signed()
  let common = match parse_common(signed, "targets") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let raw_targets = match field(signed, "targets", "signed") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let entries = match object(raw_targets, "signed.targets") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let targets : Array[TargetFile] = []
  for entry in entries {
    let (path, raw_target) = entry
    let target = match target_file(path, raw_target) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    targets.push(target)
  }
  let delegations = match signed.field("delegations") {
    None => None
    Some(raw) =>
      match parse_delegations(raw) {
        Ok(value) => Some(value)
        Err(error) => return Err(error)
      }
  }
  Ok({ envelope, common, targets, delegations })
}
