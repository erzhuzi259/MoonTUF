///|
/// Accept a newer timestamp under the current root. This is the first online
/// metadata step; it pins the snapshot version and protects later stages from
/// rollback. The caller should persist the returned raw timestamp atomically.
pub fn Client::accept_timestamp(
  self : Client,
  raw : Bytes,
) -> Result[Client, ClientError] {
  match self.check_root_chain_fresh() {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  match guard_size("timestamp", raw, self.budget.max_timestamp_bytes) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  let candidate = match
    @model.parse_timestamp(
      raw,
      limits=wire_limits(self.budget.max_timestamp_bytes, self.budget),
    ) {
    Ok(value) => value
    Err(error) => return Err(Model(error))
  }
  match @trust.verify_top_level(self.root, "timestamp", candidate.envelope()) {
    Ok(_) => ()
    Err(error) => return Err(Trust(error))
  }
  let previous_timestamp = match self.timestamp {
    Some(value) => Some(value)
    None => self.timestamp_baseline
  }
  if previous_timestamp is Some(previous) {
    let old_version = previous.common().version()
    let new_version = candidate.common().version()
    if new_version < old_version {
      return Err(Rollback("timestamp", old_version, new_version))
    }
    if new_version == old_version {
      if @model.expired(candidate.common().expires(), self.update_start) {
        return Err(Expired("timestamp"))
      }
      return Err(Unchanged("timestamp", new_version))
    }
    let old_snapshot = previous.snapshot().version()
    let new_snapshot = candidate.snapshot().version()
    if new_snapshot < old_snapshot {
      return Err(Rollback("timestamp.snapshot", old_snapshot, new_snapshot))
    }
  }
  if @model.expired(candidate.common().expires(), self.update_start) {
    return Err(Expired("timestamp"))
  }
  Ok({
    root: self.root,
    timestamp: Some(candidate),
    timestamp_baseline: Some(candidate),
    snapshot: None,
    previous_snapshot: match self.snapshot {
      Some(value) => Some(value)
      None => self.previous_snapshot
    },
    targets: None,
    update_start: self.update_start,
    budget: self.budget,
    root_rotations: self.root_rotations,
    root_chain_complete: self.root_chain_complete,
  })
}

///|
pub fn Client::snapshot_request_name(
  self : Client,
) -> Result[String, ClientError] {
  let timestamp = match self.timestamp {
    Some(value) => value
    None => return Err(MissingStage("timestamp"))
  }
  let version = timestamp.snapshot().version()
  if self.root.consistent_snapshot() {
    Ok(version.to_string() + ".snapshot.json")
  } else {
    Ok("snapshot.json")
  }
}
