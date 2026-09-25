///|
priv enum SearchOutcome {
  Found(ResolvedTarget)
  Miss
  Terminated
}

///|
/// Evidence of which verified role chain authorized a target descriptor.
/// The first element is always the top-level targets role.
pub struct ResolvedTarget {
  descriptor : @model.TargetFile
  role_chain : Array[String]
}

///|
pub fn ResolvedTarget::descriptor(self : ResolvedTarget) -> @model.TargetFile {
  self.descriptor
}

///|
pub fn ResolvedTarget::role_chain(self : ResolvedTarget) -> Array[String] {
  self.role_chain.copy()
}

///|
fn Client::delegated_name(
  self : Client,
  role_name : String,
  descriptor : @model.MetaFile,
) -> String {
  let base = role_name + ".json"
  if self.root.consistent_snapshot() {
    descriptor.version().to_string() + "." + base
  } else {
    base
  }
}

///|
/// Read and validate exactly one delegated targets role. The parent delegation
/// policy authorizes its signatures; the trusted snapshot pins its version and
/// optional raw length/hash. A parsed file is never treated as trusted alone.
fn Client::load_delegated(
  self : Client,
  parent : @model.Delegations,
  role : @model.DelegatedRole,
  load : (String) -> Bytes?,
) -> Result[@model.Targets, ClientError] {
  let role_name = role.name()
  let meta_name = role_name + ".json"
  let snapshot = match self.snapshot {
    Some(value) => value
    None => return Err(MissingStage("snapshot"))
  }
  let descriptor = match snapshot.metafile(meta_name) {
    Some(value) => value
    None => return Err(MissingDescriptor(meta_name))
  }
  let request_name = self.delegated_name(role_name, descriptor)
  let raw = match load(request_name) {
    Some(value) => value
    None => return Err(MetadataUnavailable(request_name))
  }
  match
    check_metafile(
      "delegated:" + role_name,
      raw,
      descriptor,
      self.budget.max_targets_bytes,
    ) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  let parsed = match
    @model.parse_targets(
      raw,
      limits=wire_limits(self.budget.max_targets_bytes, self.budget),
    ) {
    Ok(value) => value
    Err(error) => return Err(Model(error))
  }
  match @trust.verify_delegated(parent, role, parsed.envelope()) {
    Ok(_) => ()
    Err(error) => return Err(Trust(error))
  }
  let actual = parsed.common().version()
  let expected = descriptor.version()
  if actual != expected {
    return Err(VersionMismatch(meta_name, expected, actual))
  }
  if @model.expired(parsed.common().expires(), self.update_start) {
    return Err(Expired(meta_name))
  }
  Ok(parsed)
}

///|
/// The visited set is shared across the depth-first walk, as required to
/// avoid revisiting a role through another branch of a delegation graph.
fn Client::search_delegations(
  self : Client,
  current : @model.Targets,
  path : String,
  load : (String) -> Bytes?,
  visited : Array[String],
  chain : Array[String],
) -> Result[SearchOutcome, ClientError] {
  let delegations = match current.delegations() {
    Some(value) => value
    None => return Ok(Miss)
  }
  for role in delegations.roles() {
    if !role.matches_path(path) {
      continue
    }
    let name = role.name()
    if visited.contains(name) {
      continue
    }
    if visited.length() >= self.budget.max_delegated_roles {
      return Err(DelegationLimit(self.budget.max_delegated_roles))
    }
    visited.push(name)
    let child_chain = chain.copy()
    child_chain.push(name)
    let child = match self.load_delegated(delegations, role, load) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    if child.target(path) is Some(found) {
      return Ok(Found({ descriptor: found, role_chain: child_chain, }))
    }
    let deeper = match
      self.search_delegations(child, path, load, visited, child_chain) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    match deeper {
      Found(_) as found => return Ok(found)
      Terminated => return Ok(Terminated)
      Miss => ()
    }
    if role.terminating() {
      return Ok(Terminated)
    }
  }
  Ok(Miss)
}

///|
/// Locate a trusted target through top-level metadata and then a bounded,
/// ordered, pre-order delegated-role walk. The host supplies raw metadata by
/// repository filename; unavailable or invalid matching metadata is an error.
pub fn Client::find_target(
  self : Client,
  path : String,
  load : (String) -> Bytes?,
) -> Result[@model.TargetFile, ClientError] {
  match self.find_target_detail(path, load) {
    Ok(value) => Ok(value.descriptor())
    Err(error) => Err(error)
  }
}

///|
/// Resolve a target and retain its verified delegation chain for audit.
pub fn Client::find_target_detail(
  self : Client,
  path : String,
  load : (String) -> Bytes?,
) -> Result[ResolvedTarget, ClientError] {
  if !self.ready() {
    return Err(MissingStage("complete metadata chain"))
  }
  if !@model.safe_target_path(path) {
    return Err(InvalidPath(path))
  }
  let top = match self.targets {
    Some(value) => value
    None => return Err(MissingStage("targets"))
  }
  if top.target(path) is Some(found) {
    return Ok({ descriptor: found, role_chain: ["targets"], })
  }
  let visited : Array[String] = []
  match self.search_delegations(top, path, load, visited, ["targets"]) {
    Ok(Found(found)) => Ok(found)
    Ok(Miss | Terminated) => Err(TargetNotFound(path))
    Err(error) => Err(error)
  }
}

///|
/// Verify bytes for a target found through either top-level or delegated
/// metadata. The loader is used only for matching delegated metadata.
pub fn Client::verify_target(
  self : Client,
  path : String,
  candidate : Bytes,
  load : (String) -> Bytes?,
) -> Result[VerifiedTarget, ClientError] {
  let descriptor = match self.find_target(path, load) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  match
    guard_target_size("target:" + path, candidate, self.budget.max_target_bytes) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  if candidate.length().to_int64() != descriptor.length() {
    return Err(
      LengthMismatch(
        "target:" + path,
        descriptor.length(),
        candidate.length().to_int64(),
      ),
    )
  }
  if !@crypto.matches_sha256(candidate, descriptor.sha256()) {
    return Err(HashMismatch("target:" + path))
  }
  Ok({ path, bytes: candidate, sha256: descriptor.sha256(), })
}

///|
pub fn Client::target_request_name(
  self : Client,
  path : String,
  load : (String) -> Bytes?,
) -> Result[String, ClientError] {
  let descriptor = match self.find_target(path, load) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  if !self.root.consistent_snapshot() {
    return Ok(path)
  }
  let parts : Array[String] = path
    .split("/")
    .map(part => part.to_owned())
    .collect()
  let mut result = descriptor.sha256() + "." + parts[parts.length() - 1]
  let mut index = parts.length() - 2
  while index >= 0 {
    result = parts[index] + "/" + result
    index -= 1
  }
  Ok(result)
}
