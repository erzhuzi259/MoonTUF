///|
pub(all) enum ClientError {
  Model(@model.ModelError)
  Trust(@trust.TrustError)
  InvalidStartTime(String)
  ClockRollback(String, String)
  Expired(String)
  MissingStage(String)
  VersionMismatch(String, Int, Int)
  Rollback(String, Int, Int)
  Unchanged(String, Int)
  ResourceLimit(String, Int, Int)
  TargetResourceLimit(String, Int64, Int64)
  LengthMismatch(String, Int64, Int64)
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
  max_target_bytes : Int64
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
  max_target_bytes? : Int64 = 64L * 1024L * 1024L,
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
    max_target_bytes: bounded_budget64(max_target_bytes, 1L << 40),
    max_root_rotations: bounded_budget(max_root_rotations, 1024),
    max_delegated_roles: bounded_budget(max_delegated_roles, 64),
    max_json_depth: bounded_budget(max_json_depth, 256),
    max_json_nodes: bounded_budget(max_json_nodes, 1000000),
  }
}

///|
fn bounded_budget(value : Int, ceiling : Int) -> Int {
  if value < 1 {
    1
  } else if value > ceiling {
    ceiling
  } else {
    value
  }
}

///|
fn bounded_budget64(value : Int64, ceiling : Int64) -> Int64 {
  if value < 1L {
    1L
  } else if value > ceiling {
    ceiling
  } else {
    value
  }
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
fn guard_size(
  label : String,
  bytes : Bytes,
  maximum : Int,
) -> Result[Unit, ClientError] {
  if bytes.length() > maximum {
    Err(ResourceLimit(label, bytes.length(), maximum))
  } else {
    Ok(())
  }
}

///|
fn guard_target_size(
  label : String,
  bytes : Bytes,
  maximum : Int64,
) -> Result[Unit, ClientError] {
  let size = bytes.length().to_int64()
  if size > maximum {
    Err(TargetResourceLimit(label, size, maximum))
  } else {
    Ok(())
  }
}

///|
pub struct Client {
  root : @model.Root
  timestamp : @model.Timestamp?
  timestamp_baseline : @model.Timestamp?
  snapshot : @model.Snapshot?
  previous_snapshot : @model.Snapshot?
  targets : @model.Targets?
  update_start : String
  budget : Budgets
  root_rotations : Int
  root_chain_complete : Bool
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
pub fn Client::update_start(self : Client) -> String {
  self.update_start
}

///|
/// Start another update cycle while retaining rollback baselines. The host
/// supplies one fixed UTC instant for the whole cycle; moving the clock
/// backwards relative to the last cycle is rejected rather than silently
/// reviving expired metadata.
pub fn Client::begin_update(
  self : Client,
  new_start : String,
) -> Result[Client, ClientError] {
  if !@model.valid_utc_time(new_start) {
    return Err(InvalidStartTime(new_start))
  }
  if new_start < self.update_start {
    return Err(ClockRollback(self.update_start, new_start))
  }
  Ok({
    root: self.root,
    timestamp: self.timestamp,
    timestamp_baseline: self.timestamp_baseline,
    snapshot: self.snapshot,
    previous_snapshot: self.previous_snapshot,
    targets: self.targets,
    update_start: new_start,
    budget: self.budget,
    root_rotations: 0,
    root_chain_complete: self.root_chain_complete,
  })
}

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
  let root = match
    @model.parse_root(
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
    timestamp_baseline: None,
    snapshot: None,
    previous_snapshot: None,
    targets: None,
    update_start,
    budget,
    root_rotations: 0,
    root_chain_complete: true,
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
  self.check_complete_fresh() is Ok(_)
}

///|
/// A retained chain can become stale at the start of a later update cycle.
/// This returns the first missing or expired role instead of silently treating
/// an unchanged timestamp as a usable complete update.
pub fn Client::check_complete_fresh(self : Client) -> Result[Unit, ClientError] {
  if !self.root_chain_complete {
    return Err(MissingStage("root chain"))
  }
  match self.check_root_fresh() {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  let timestamp = match self.timestamp {
    Some(value) => value
    None => return Err(MissingStage("timestamp"))
  }
  let snapshot = match self.snapshot {
    Some(value) => value
    None => return Err(MissingStage("snapshot"))
  }
  let targets = match self.targets {
    Some(value) => value
    None => return Err(MissingStage("targets"))
  }
  if @model.expired(timestamp.common().expires(), self.update_start) {
    return Err(Expired("timestamp"))
  }
  if @model.expired(snapshot.common().expires(), self.update_start) {
    return Err(Expired("snapshot"))
  }
  if @model.expired(targets.common().expires(), self.update_start) {
    return Err(Expired("targets"))
  }
  Ok(())
}
