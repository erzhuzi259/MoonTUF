///|
/// Check a child's raw envelope against an authenticated parent descriptor.
/// The hash is over raw bytes, not canonical signed JSON.
fn check_metafile(
  name : String,
  raw : Bytes,
  description : @model.MetaFile,
  maximum : Int,
) -> Result[Unit, ClientError] {
  match guard_size(name, raw, maximum) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  match description.length() {
    Some(expected) =>
      if raw.length() != expected {
        return Err(
          LengthMismatch(name, expected.to_int64(), raw.length().to_int64()),
        )
      }
    None => ()
  }
  match description.sha256() {
    Some(expected) =>
      if !@crypto.matches_sha256(raw, expected) {
        return Err(HashMismatch(name))
      }
    None => ()
  }
  Ok(())
}

///|
/// Accept a snapshot pinned by the trusted timestamp. Every metadata filename
/// previously listed remains present and cannot decrease in version.
pub fn Client::accept_snapshot(
  self : Client,
  raw : Bytes,
) -> Result[Client, ClientError] {
  let timestamp = match self.timestamp {
    Some(value) => value
    None => return Err(MissingStage("timestamp"))
  }
  match self.check_root_fresh() {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  match
    check_metafile(
      "snapshot",
      raw,
      timestamp.snapshot(),
      self.budget.max_snapshot_bytes,
    ) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  let candidate = match
    @model.parse_snapshot(
      raw,
      limits=wire_limits(self.budget.max_snapshot_bytes, self.budget),
    ) {
    Ok(value) => value
    Err(error) => return Err(Model(error))
  }
  match @trust.verify_top_level(self.root, "snapshot", candidate.envelope()) {
    Ok(_) => ()
    Err(error) => return Err(Trust(error))
  }
  let expected = timestamp.snapshot().version()
  let actual = candidate.common().version()
  if actual != expected {
    return Err(VersionMismatch("snapshot", expected, actual))
  }
  if self.previous_snapshot is Some(previous) {
    for old_entry in previous.metafiles() {
      let (name, old_file) = old_entry
      let new_file = match candidate.metafile(name) {
        Some(value) => value
        None => return Err(Rollback("snapshot." + name, old_file.version(), 0))
      }
      if new_file.version() < old_file.version() {
        return Err(
          Rollback("snapshot." + name, old_file.version(), new_file.version()),
        )
      }
    }
  }
  if @model.expired(candidate.common().expires(), self.update_start) {
    return Err(Expired("snapshot"))
  }
  Ok({
    root: self.root,
    timestamp: self.timestamp,
    snapshot: Some(candidate),
    previous_snapshot: Some(candidate),
    targets: None,
    update_start: self.update_start,
    budget: self.budget,
    root_rotations: self.root_rotations,
  })
}

///|
pub fn Client::targets_request_name(
  self : Client,
) -> Result[String, ClientError] {
  let snapshot = match self.snapshot {
    Some(value) => value
    None => return Err(MissingStage("snapshot"))
  }
  let descriptor = match snapshot.metafile("targets.json") {
    Some(value) => value
    None => return Err(MissingDescriptor("targets.json"))
  }
  if self.root.consistent_snapshot() {
    Ok(descriptor.version().to_string() + ".targets.json")
  } else {
    Ok("targets.json")
  }
}
