///|
/// TAP 15 hash-bin delegation; never allocate 2^bit_length role objects.
pub struct SuccinctRoles {
  keyids : Array[String]
  threshold : Int32
  bit_length : Int32
  name_prefix : String
}

///|
pub fn SuccinctRoles::bit_length(self : SuccinctRoles) -> Int32 {
  self.bit_length
}

///|
pub fn SuccinctRoles::name_prefix(self : SuccinctRoles) -> String {
  self.name_prefix
}

///|
pub fn SuccinctRoles::role_for_path(
  self : SuccinctRoles,
  path : String,
) -> DelegatedRole {
  let digest = @crypto.sha256(@utf8.encode(path))
  let mut number = 0UL
  for i = 0; i < 4; i = i + 1 {
    number = (number << 8) | digest[i].to_uint64()
  }
  number = number >> (32 - self.bit_length)
  let width = (self.bit_length + 3) / 4
  let chars : Array[Char] = []
  let digits : Array[Char] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
  ]
  for i = width - 1; i >= 0; i = i - 1 {
    chars.push(digits[((number >> (i * 4)) & 15UL).to_int()])
  }
  {
    name: self.name_prefix + "-" + String::from_array(chars[:]),
    keyids: self.keyids,
    threshold: self.threshold,
    paths: Some(["*"]),
    path_hash_prefixes: None,
    terminating: true,
  }
}

///|
fn parse_succinct(
  raw : @wire.Value,
  ids : Array[String],
) -> Result[SuccinctRoles, ModelError] {
  let policy = match read_role("succinct", raw, ids) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let bits = match
    positive_field(raw, "bit_length", "signed.delegations.succinct_roles") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let prefix = match
    text_field(raw, "name_prefix", "signed.delegations.succinct_roles") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  if bits > 32 || !safe_target_path(prefix) {
    return Err(
      InvalidValue("succinct_roles", "invalid bit length or role prefix"),
    )
  }
  Ok({
    keyids: policy.keyids(),
    threshold: policy.threshold(),
    bit_length: bits,
    name_prefix: prefix,
  })
}

///|
pub fn Delegations::succinct_roles(self : Delegations) -> SuccinctRoles? {
  self.succinct
}

///|
pub fn Delegations::roles_for_path(
  self : Delegations,
  path : String,
) -> Array[DelegatedRole] {
  match self.succinct {
    Some(succinct) => [succinct.role_for_path(path)]
    None => self.roles.copy()
  }
}
