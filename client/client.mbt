///|
pub(all) enum ClientError {
  Model(@model.ModelError)
  Trust(@trust.TrustError)
  InvalidStartTime(String)
  Expired(String)
  MissingStage(String)
  VersionMismatch(String, Int, Int)
  Rollback(String, Int, Int)
  Unchanged(String, Int)
  ResourceLimit(String, Int, Int)
  LengthMismatch(String, Int, Int)
  HashMismatch(String)
  MissingDescriptor(String)
  RootRotationLimit(Int)
  TargetNotFound(String)
  MetadataUnavailable(String)
  DelegationLimit(Int)
  AlreadyFinished
  CheckpointMalformed(String)
  CheckpointRootMismatch
  InvalidPath(String)
} derive(Debug)

///|
/// Budgets protect the caller from untrusted metadata and target-file input.
/// They are enforced before parsing or hashing and are never inferred from
/// untrusted length fields alone.
pub struct Budgets {
  max_root_bytes : Int
  max_timestamp_bytes : Int
  max_snapshot_bytes : Int
  max_targets_bytes : Int
  max_target_bytes : Int
  max_root_rotations : Int
  max_delegated_roles : Int
  max_json_depth : Int
  max_json_nodes : Int
}

///|
pub fn budgets(
  max_root_bytes? : Int = 512 * 1024,
  max_timestamp_bytes? : Int = 256 * 1024,
  max_snapshot_bytes? : Int = 2 * 1024 * 1024,
  max_targets_bytes? : Int = 8 * 1024 * 1024,
  max_target_bytes? : Int = 64 * 1024 * 1024,
  max_root_rotations? : Int = 32,
  max_delegated_roles? : Int = 32,
  max_json_depth? : Int = 64,
  max_json_nodes? : Int = 100000,
) -> Budgets {
  {
    max_root_bytes: bounded_budget(max_root_bytes, 16 * 1024 * 1024),
    max_timestamp_bytes: bounded_budget(max_timestamp_bytes, 16 * 1024 * 1024),
    max_snapshot_bytes: bounded_budget(max_snapshot_bytes, 256 * 1024 * 1024),
    max_targets_bytes: bounded_budget(max_targets_bytes, 256 * 1024 * 1024),
    max_target_bytes: bounded_budget(max_target_bytes, 1024 * 1024 * 1024),
    max_root_rotations: bounded_budget(max_root_rotations, 1024),
    max_delegated_roles: bounded_budget(max_delegated_roles, 1024),
    max_json_depth: bounded_budget(max_json_depth, 256),
    max_json_nodes: bounded_budget(max_json_nodes, 1000000),
  }
}

///|
fn bounded_budget(value : Int, ceiling : Int) -> Int {
  if value < 1 { 1 } else if value > ceiling { ceiling } else { value }
}

///|
fn wire_limits(max_bytes : Int, budget : Budgets) -> @wire.Limits {
  @wire.limits(
    max_bytes~,
    max_depth=budget.max_json_depth,
    max_nodes=budget.max_json_nodes,
  )
}

///|
fn guard_size(label : String, bytes : Bytes, maximum : Int) -> Result[Unit, ClientError] {
  if bytes.length() > maximum {
    Err(ResourceLimit(label, bytes.length(), maximum))
  } else {
    Ok(())
  }
}

///|
pub struct Client {
  root : @model.Root
  timestamp : @model.Timestamp?
  snapshot : @model.Snapshot?
  previous_snapshot : @model.Snapshot?
  targets : @model.Targets?
  update_start : String
  budget : Budgets
  root_rotations : Int
}

///|
pub fn Client::root_version(self : Client) -> Int {
  self.root.common().version()
}

///|
pub fn Client::timestamp_version(self : Client) -> Int? {
  self.timestamp.map(value => value.common().version())
}

///|
pub fn Client::snapshot_version(self : Client) -> Int? {
  self.snapshot.map(value => value.common().version())
}

///|
pub fn Client::targets_version(self : Client) -> Int? {
  self.targets.map(value => value.common().version())
}

///|
pub fn Client::update_start(self : Client) -> String { self.update_start }

///|
pub fn Client::consistent_snapshot(self : Client) -> Bool {
  self.root.consistent_snapshot()
}

///|
/// The caller MUST authenticate trusted_root_raw by an out-of-band mechanism
/// before passing it here. A self-signed root alone cannot bootstrap trust.
pub fn open_trusted_root(
  trusted_root_raw : Bytes,
  update_start : String,
  budget? : Budgets = budgets(),
) -> Result[Client, ClientError] {
  if !@model.valid_utc_time(update_start) {
    return Err(InvalidStartTime(update_start))
  }
  match guard_size("root", trusted_root_raw, budget.max_root_bytes) {
    Err(error) => return Err(error)
    Ok(_) => ()
  }
  let root = match @model.parse_root(
    trusted_root_raw,
    limits=wire_limits(budget.max_root_bytes, budget),
  ) {
    Ok(value) => value
    Err(error) => return Err(Model(error))
  }
  match @trust.verify_root_self(root) {
    Ok(_) => ()
    Err(error) => return Err(Trust(error))
  }
  Ok({
    root,
    timestamp: None,
    snapshot: None,
    previous_snapshot: None,
    targets: None,
    update_start,
    budget,
    root_rotations: 0,
  })
}

///|
pub fn Client::check_root_fresh(self : Client) -> Result[Unit, ClientError] {
  if @model.expired(self.root.common().expires(), self.update_start) {
    Err(Expired("root"))
  } else {
    Ok(())
  }
}

///|
pub fn Client::ready(self : Client) -> Bool {
  if self.check_root_fresh() is Err(_) { return false }
  match (self.timestamp, self.snapshot, self.targets) {
    (Some(timestamp), Some(snapshot), Some(targets)) =>
      !@model.expired(timestamp.common().expires(), self.update_start) &&
      !@model.expired(snapshot.common().expires(), self.update_start) &&
      !@model.expired(targets.common().expires(), self.update_start)
    _ => false
  }
}
