///|
/// A requested target and its full verified role chain, with the exact
/// repository filename selected by the current consistent-snapshot setting.
pub struct PlannedTarget {
  resolution : ResolvedTarget
  repository_name : String
}

///|
pub fn PlannedTarget::resolution(self : PlannedTarget) -> ResolvedTarget {
  self.resolution
}

///|
pub fn PlannedTarget::repository_name(self : PlannedTarget) -> String {
  self.repository_name
}

///|
pub struct ResolutionPlan {
  targets : Array[PlannedTarget]
  root_sha256 : String
  snapshot_version : Int32
  metadata_loads : Int32
}

///|
pub fn ResolutionPlan::targets(self : ResolutionPlan) -> Array[PlannedTarget] {
  self.targets.copy()
}

///|
pub fn ResolutionPlan::root_sha256(self : ResolutionPlan) -> String {
  self.root_sha256
}

///|
pub fn ResolutionPlan::snapshot_version(self : ResolutionPlan) -> Int32 {
  self.snapshot_version
}

///|
pub fn ResolutionPlan::metadata_loads(self : ResolutionPlan) -> Int32 {
  self.metadata_loads
}

///|
fn Client::descriptor_request_name(
  self : Client,
  descriptor : @model.TargetFile,
) -> String {
  let path = descriptor.path()
  if !self.root.consistent_snapshot() {
    return path
  }
  let parts : Array[String] = path
    .split("/")
    .map(fn(s) { s.to_owned() })
    .collect()
  let mut result = descriptor.preferred_hash().1 +
    "." +
    parts[parts.length() - 1]
  for i = parts.length() - 2; i >= 0; i = i - 1 {
    result = parts[i] + "/" + result
  }
  result
}

///|
/// Batch resolution across top-level, ordinary and succinct delegated targets.
/// Every target is authorized independently (including terminating order), but
/// immutable fetched metadata bytes are cached for the duration of this call.
/// Failure returns no partial plan. This is not automatic role enumeration.
pub fn Client::resolve_plan(
  self : Client,
  paths : Array[String],
  load : (String) -> Bytes?,
  max_targets~ : Int32 = 256,
  max_metadata~ : Int32 = 32,
) -> Result[ResolutionPlan, ClientError] {
  if !self.ready() {
    return Err(MissingStage("complete metadata chain"))
  }
  if max_targets < 0 ||
    paths.length() > max_targets ||
    max_metadata < 0 ||
    max_metadata > self.budget.max_delegated_roles {
    return Err(ResourceLimit("resolution plan", paths.length(), max_targets))
  }
  let seen : Map[String, Bool] = Map([])
  for path in paths {
    if !@model.safe_target_path(path) || seen.contains(path) {
      return Err(InvalidPath(path))
    }
    seen[path] = true
  }
  let cache : Map[String, Bytes] = Map([])
  let mut loads = 0
  let mut limited = false
  let cached_load = fn(name) {
    match cache.get(name) {
      Some(bytes) => Some(bytes)
      None => {
        if loads >= max_metadata {
          limited = true
          return None
        }
        loads += 1
        let bytes = load(name)
        if bytes is Some(value) {
          cache[name] = value
        }
        bytes
      }
    }
  }
  let targets : Array[PlannedTarget] = []
  for path in paths {
    let resolution = match self.find_target_detail(path, cached_load) {
      Ok(value) => value
      Err(error) =>
        if limited {
          return Err(DelegationLimit(max_metadata))
        } else {
          return Err(error)
        }
    }
    targets.push({
      repository_name: self.descriptor_request_name(resolution.descriptor()),
      resolution,
    })
  }
  Ok({
    targets,
    root_sha256: @crypto.sha256_hex(self.root.envelope().raw()),
    snapshot_version: self.snapshot_version().unwrap(),
    metadata_loads: loads,
  })
}
