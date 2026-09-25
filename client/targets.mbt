///|
/// Accept top-level targets metadata only after the trusted snapshot pins its
/// raw bytes and version. This step does not download or install target files.
pub fn Client::accept_targets(
  self : Client,
  raw : Bytes,
) -> Result[Client, ClientError] {
  let snapshot = match self.snapshot {
    Some(value) => value
    None => return Err(MissingStage("snapshot"))
  }
  let descriptor = match snapshot.metafile("targets.json") {
    Some(value) => value
    None => return Err(MissingDescriptor("targets.json"))
  }
  match
    check_metafile("targets", raw, descriptor, self.budget.max_targets_bytes) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  let candidate = match
    @model.parse_targets(
      raw,
      limits=wire_limits(self.budget.max_targets_bytes, self.budget),
    ) {
    Ok(value) => value
    Err(error) => return Err(Model(error))
  }
  match @trust.verify_top_level(self.root, "targets", candidate.envelope()) {
    Ok(_) => ()
    Err(error) => return Err(Trust(error))
  }
  let expected = descriptor.version()
  let actual = candidate.common().version()
  if actual != expected {
    return Err(VersionMismatch("targets", expected, actual))
  }
  if @model.expired(candidate.common().expires(), self.update_start) {
    return Err(Expired("targets"))
  }
  Ok({
    root: self.root,
    timestamp: self.timestamp,
    snapshot: self.snapshot,
    previous_snapshot: self.previous_snapshot,
    targets: Some(candidate),
    update_start: self.update_start,
    budget: self.budget,
    root_rotations: self.root_rotations,
  })
}

///|
pub fn Client::top_level_target(
  self : Client,
  path : String,
) -> Result[@model.TargetFile, ClientError] {
  if !self.ready() {
    return Err(MissingStage("complete metadata chain"))
  }
  if !@model.safe_target_path(path) {
    return Err(InvalidPath(path))
  }
  let targets = match self.targets {
    Some(value) => value
    None => return Err(MissingStage("targets"))
  }
  match targets.target(path) {
    Some(value) => Ok(value)
    None => Err(TargetNotFound(path))
  }
}
