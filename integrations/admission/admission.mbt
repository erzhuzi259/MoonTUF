///|
/// Host-side admission policy. TUF establishes authenticity; this policy
/// narrows which authentic targets a particular host is willing to stage.
pub struct Policy {
  prefix : String
  max_bytes : Int64
  allowed_final_roles : Array[String]
}

///|
pub(all) enum AdmissionError {
  InvalidPolicy(String)
  OutsideNamespace(String)
  RoleNotAllowed(String)
  TooLarge(Int64, Int64)
  Client(@client.ClientError)
  StaleTicket
} derive(Debug)

///|
pub fn policy(
  prefix? : String = "",
  max_bytes? : Int64 = 512L * 1024L * 1024L,
  allowed_final_roles? : Array[String] = [],
) -> Result[Policy, AdmissionError] {
  if prefix != "" && !@model.safe_target_path(prefix) {
    return Err(InvalidPolicy("unsafe namespace"))
  }
  if max_bytes < 1L {
    return Err(InvalidPolicy("max_bytes must be positive"))
  }
  let roles = allowed_final_roles.copy()
  for role in roles {
    if role == "" ||
      role.contains("/") ||
      role.contains("\\") ||
      role.contains("..") {
      return Err(InvalidPolicy("invalid final role"))
    }
  }
  Ok({ prefix, max_bytes, allowed_final_roles: roles, })
}

///|
pub fn Policy::prefix(self : Policy) -> String {
  self.prefix
}

///|
pub fn Policy::max_bytes(self : Policy) -> Int64 {
  self.max_bytes
}

///|
pub fn Policy::allowed_final_roles(self : Policy) -> Array[String] {
  self.allowed_final_roles.copy()
}

///|
/// A ticket is a proposed download, not authorization to install. Its
/// repository path is derived from trusted target metadata; the host should
/// fetch into a temporary location and verify the bytes before publication.
pub struct Ticket {
  path : String
  repository_name : String
  length : Int64
  sha256 : String
  root_version : Int
  snapshot_version : Int
  target_role_chain : Array[String]
}

///|
pub fn Ticket::path(self : Ticket) -> String {
  self.path
}

///|
pub fn Ticket::repository_name(self : Ticket) -> String {
  self.repository_name
}

///|
pub fn Ticket::length(self : Ticket) -> Int64 {
  self.length
}

///|
pub fn Ticket::sha256(self : Ticket) -> String {
  self.sha256
}

///|
pub fn Ticket::root_version(self : Ticket) -> Int {
  self.root_version
}

///|
pub fn Ticket::snapshot_version(self : Ticket) -> Int {
  self.snapshot_version
}

///|
pub fn Ticket::target_role_chain(self : Ticket) -> Array[String] {
  self.target_role_chain.copy()
}

///|
pub(all) enum Admission {
  Current
  Download(Ticket)
}

///|
fn allowed_namespace(policy : Policy, path : String) -> Bool {
  if policy.prefix == "" {
    return true
  }
  path.has_prefix(policy.prefix + "/")
}

///|
fn allowed_role(policy : Policy, chain : Array[String]) -> Bool {
  if policy.allowed_final_roles.length() == 0 {
    return true
  }
  let final_role = chain[chain.length() - 1]
  policy.allowed_final_roles.contains(final_role)
}

///|
/// Evaluate one target path against both TUF trust and host policy. A matching
/// installed digest yields Current; no unverified bytes are touched.
pub fn evaluate(
  client : @client.Client,
  path : String,
  policy : Policy,
  load : (String) -> Bytes?,
  installed_sha256? : String = "",
) -> Result[Admission, AdmissionError] {
  if !@model.safe_target_path(path) {
    return Err(OutsideNamespace(path))
  }
  if !allowed_namespace(policy, path) {
    return Err(OutsideNamespace(path))
  }
  let resolved = match client.find_target_detail(path, load) {
    Ok(value) => value
    Err(error) => return Err(Client(error))
  }
  let descriptor = resolved.descriptor()
  if descriptor.length() > policy.max_bytes {
    return Err(TooLarge(descriptor.length(), policy.max_bytes))
  }
  let chain = resolved.role_chain()
  if !allowed_role(policy, chain) {
    return Err(RoleNotAllowed(chain[chain.length() - 1]))
  }
  if installed_sha256 != "" &&
    installed_sha256.to_lower() == descriptor.sha256() {
    return Ok(Current)
  }
  let repository_name = match client.target_request_name(path, load) {
    Ok(value) => value
    Err(error) => return Err(Client(error))
  }
  let snapshot_version = match client.snapshot_version() {
    Some(value) => value
    None => return Err(Client(@client.MissingStage("snapshot")))
  }
  Ok(
    Download({
      path,
      repository_name,
      length: descriptor.length(),
      sha256: descriptor.sha256(),
      root_version: client.root_version(),
      snapshot_version,
      target_role_chain: chain,
    }),
  )
}

///|
/// Re-resolve against the same trusted state and verify the exact candidate
/// bytes. If the client state has changed, the ticket must be re-evaluated.
pub fn verify_download(
  client : @client.Client,
  ticket : Ticket,
  candidate : Bytes,
  load : (String) -> Bytes?,
) -> Result[@client.VerifiedTarget, AdmissionError] {
  if client.root_version() != ticket.root_version ||
    client.snapshot_version() != Some(ticket.snapshot_version) {
    return Err(StaleTicket)
  }
  let resolved = match client.find_target_detail(ticket.path, load) {
    Ok(value) => value
    Err(error) => return Err(Client(error))
  }
  let descriptor = resolved.descriptor()
  if descriptor.length() != ticket.length ||
    descriptor.sha256() != ticket.sha256 {
    return Err(StaleTicket)
  }
  if resolved.role_chain() != ticket.target_role_chain {
    return Err(StaleTicket)
  }
  match client.verify_target(ticket.path, candidate, load) {
    Ok(value) => Ok(value)
    Err(error) => Err(Client(error))
  }
}

///|
/// For large files the host can avoid buffering the entire candidate.
/// It must still hold a temporary file inaccessible to installers until the
/// returned TargetStream has finished successfully.
pub fn open_download_stream(
  client : @client.Client,
  ticket : Ticket,
  load : (String) -> Bytes?,
) -> Result[@client.TargetStream, AdmissionError] {
  if client.root_version() != ticket.root_version ||
    client.snapshot_version() != Some(ticket.snapshot_version) {
    return Err(StaleTicket)
  }
  let resolved = match client.find_target_detail(ticket.path, load) {
    Ok(value) => value
    Err(error) => return Err(Client(error))
  }
  let descriptor = resolved.descriptor()
  if descriptor.length() != ticket.length ||
    descriptor.sha256() != ticket.sha256 {
    return Err(StaleTicket)
  }
  if resolved.role_chain() != ticket.target_role_chain {
    return Err(StaleTicket)
  }
  match client.open_stream(ticket.path, load) {
    Ok(value) => Ok(value)
    Err(error) => Err(Client(error))
  }
}
