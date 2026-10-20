///|
/// A target descriptor binds one relative target path to exact bytes.
pub struct TargetFile {
  path : String
  length : Int64
  hashes : Array[(String, String)]
  sha256 : String
  custom : @wire.Value?
}

///|
pub fn TargetFile::path(self : TargetFile) -> String {
  self.path
}

///|
pub fn TargetFile::length(self : TargetFile) -> Int64 {
  self.length
}

///|
pub fn TargetFile::hashes(self : TargetFile) -> Array[(String, String)] {
  self.hashes.copy()
}

///|
pub fn TargetFile::preferred_hash(self : TargetFile) -> (String, String) {
  match hash_value(self.hashes, "sha256") {
    Some(value) => ("sha256", value)
    None => ("sha512", hash_value(self.hashes, "sha512").unwrap_or(""))
  }
}

///|
pub fn TargetFile::sha256(self : TargetFile) -> String {
  self.sha256
}

///|
/// Custom policy data is detached from the parsed metadata, including all
/// nested arrays and objects, so callers cannot mutate a trusted descriptor.
pub fn TargetFile::custom(self : TargetFile) -> @wire.Value? {
  self.custom.map(copy_wire_value)
}

///|
pub fn safe_target_path(path : String) -> Bool {
  let bytes = @utf8.encode(path)
  if bytes.length() == 0 || bytes.length() > 4096 {
    return false
  }
  if bytes[0].to_int() == 47 || bytes[0].to_int() == 92 {
    return false
  }
  if path.contains("\\") || path.contains(":") {
    return false
  }
  let segments : Array[String] = path
    .split("/")
    .map(part => part.to_owned())
    .collect()
  for segment in segments {
    if segment == "" || segment == "." || segment == ".." {
      return false
    }
  }
  for byte in bytes {
    let ch = byte.to_int()
    if ch < 32 || ch == 127 {
      return false
    }
  }
  true
}

///|
fn target_file(
  path : String,
  raw : @wire.Value,
) -> Result[TargetFile, ModelError] {
  if !safe_target_path(path) {
    return Err(InvalidValue("signed.targets." + path, "unsafe target path"))
  }
  ignore(
    match object(raw, "signed.targets." + path) {
      Ok(entries) => entries
      Err(error) => return Err(error)
    },
  )
  let length_value = match field(raw, "length", "signed.targets." + path) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let length = match
    nonnegative_int64(length_value, "signed.targets." + path + ".length") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let hashes = match read_hashes(raw, "signed.targets." + path, true) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let sha256 = hash_value(hashes, "sha256").unwrap_or("")
  let custom = match raw.field("custom") {
    None => None
    Some(value) =>
      match value.as_dict() {
        Some(_) => Some(value)
        None => return Err(WrongType("signed.targets." + path + ".custom"))
      }
  }
  Ok({ path, length, hashes, sha256, custom, })
}

///|
pub struct DelegatedRole {
  name : String
  keyids : Array[String]
  threshold : Int32
  paths : Array[String]?
  path_hash_prefixes : Array[String]?
  terminating : Bool
}

///|
pub fn DelegatedRole::name(self : DelegatedRole) -> String {
  self.name
}

///|
pub fn DelegatedRole::keyids(self : DelegatedRole) -> Array[String] {
  self.keyids.copy()
}

///|
pub fn DelegatedRole::threshold(self : DelegatedRole) -> Int32 {
  self.threshold
}

///|
pub fn DelegatedRole::paths(self : DelegatedRole) -> Array[String]? {
  self.paths.map(items => items.copy())
}

///|
pub fn DelegatedRole::path_hash_prefixes(
  self : DelegatedRole,
) -> Array[String]? {
  self.path_hash_prefixes.map(items => items.copy())
}

///|
pub fn DelegatedRole::terminating(self : DelegatedRole) -> Bool {
  self.terminating
}

///|
pub struct Delegations {
  keys : Array[PublicKey]
  roles : Array[DelegatedRole]
  succinct : SuccinctRoles?
}

///|
pub fn Delegations::keys(self : Delegations) -> Array[PublicKey] {
  self.keys.copy()
}

///|
pub fn Delegations::roles(self : Delegations) -> Array[DelegatedRole] {
  self.roles.copy()
}

///|
pub fn Delegations::key(self : Delegations, keyid : String) -> PublicKey? {
  for key in self.keys {
    if key.keyid() == keyid {
      return Some(key)
    }
  }
  None
}

///|
fn string_list(
  raw : @wire.Value,
  path : String,
) -> Result[Array[String], ModelError] {
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
fn delegated_role(
  raw : @wire.Value,
  known_keyids : Array[String],
) -> Result[DelegatedRole, ModelError] {
  ignore(
    match object(raw, "signed.delegations.roles[]") {
      Ok(value) => value
      Err(error) => return Err(error)
    },
  )
  let parent = "signed.delegations.roles[]"
  let name = match text_field(raw, "name", parent) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  if !safe_role_name(name) {
    return Err(InvalidValue(parent + ".name", "unsafe or reserved role name"))
  }
  let role_keys = match read_role(name, raw, known_keyids) {
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
    return Err(
      InvalidValue(
        parent, "exactly one of paths or path_hash_prefixes is required",
      ),
    )
  }
  if paths is Some(items) {
    for item in items {
      if item == "" ||
        @utf8.encode(item).length() > 1024 ||
        item.contains("\\") ||
        item.contains("..") {
        return Err(InvalidValue(parent + ".paths", "unsafe path pattern"))
      }
    }
  }
  if prefixes is Some(items) {
    for item in items {
      if item.length() == 0 || item.length() > 64 {
        return Err(
          InvalidValue(parent + ".path_hash_prefixes", "invalid prefix length"),
        )
      }
      for byte in @utf8.encode(item) {
        let ch = byte.to_int()
        if !((ch >= 48 && ch <= 57) || (ch >= 97 && ch <= 102)) {
          return Err(
            InvalidValue(
              parent + ".path_hash_prefixes",
              "prefix must be lowercase hex",
            ),
          )
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
  ignore(
    match object(raw, "signed.delegations") {
      Ok(value) => value
      Err(error) => return Err(error)
    },
  )
  let key_values = match field(raw, "keys", "signed.delegations") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let key_entries = match object(key_values, "signed.delegations.keys") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let keys : Array[PublicKey] = []
  let known_keyids : Array[String] = []
  for entry in key_entries {
    let (keyid, raw_key) = entry
    let key = match read_key(keyid, raw_key) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    keys.push(key)
    known_keyids.push(keyid)
  }
  known_keyids.sort()
  if raw.field("succinct_roles") is Some(value) {
    if raw.field("roles") is Some(_) {
      return Err(
        InvalidValue("delegations", "roles and succinct_roles are exclusive"),
      )
    }
    let succinct = match parse_succinct(value, known_keyids) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    return Ok({ keys, roles: [], succinct: Some(succinct), })
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
    let role = match delegated_role(raw_role, known_keyids) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    names.push(role.name())
    roles.push(role)
  }
  if sorted_duplicate(names) is Some(name) {
    return Err(DuplicateItem("signed.delegations.roles[].name=" + name))
  }
  Ok({ keys, roles, succinct: None, })
}

///|
pub struct Targets {
  envelope : Envelope
  common : Common
  targets : Array[TargetFile]
  delegations : Delegations?
}

///|
pub fn Targets::envelope(self : Targets) -> Envelope {
  self.envelope
}

///|
pub fn Targets::common(self : Targets) -> Common {
  self.common
}

///|
pub fn Targets::targets(self : Targets) -> Array[TargetFile] {
  self.targets.copy()
}

///|
pub fn Targets::delegations(self : Targets) -> Delegations? {
  self.delegations
}

///|
pub fn Targets::target(self : Targets, path : String) -> TargetFile? {
  for target in self.targets {
    if target.path() == path {
      return Some(target)
    }
  }
  None
}

///|
pub fn parse_targets(
  raw : Bytes,
  limits~ : @wire.Limits = @wire.limits(),
) -> Result[Targets, ModelError] {
  let envelope = match parse_envelope(raw, limits~) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let signed = envelope.signed
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
  Ok({ envelope, common, targets, delegations, })
}
