///|
/// Advance one and only one version of root metadata. Both the previously
/// trusted root and the proposed root must authorize the same signed bytes.
/// A caller can repeat this step until version N+1 is unavailable, then call
/// finish_root_chain before attempting timestamp.
pub fn Client::advance_root(self : Client, candidate_raw : Bytes) -> Result[Client, ClientError] {
  if self.root_rotations >= self.budget.max_root_rotations {
    return Err(RootRotationLimit(self.budget.max_root_rotations))
  }
  match guard_size("root", candidate_raw, self.budget.max_root_bytes) {
    Err(error) => return Err(error)
    Ok(_) => ()
  }
  let candidate = match @model.parse_root(
    candidate_raw,
    limits=wire_limits(self.budget.max_root_bytes, self.budget),
  ) {
    Ok(value) => value
    Err(error) => return Err(Model(error))
  }
  let current_version = self.root.common().version()
  let next_version = candidate.common().version()
  if current_version == 2147483647 {
    return Err(RootRotationLimit(self.budget.max_root_rotations))
  }
  if next_version != current_version + 1 {
    return Err(VersionMismatch("root", current_version + 1, next_version))
  }
  match @trust.verify_top_level(self.root, "root", candidate.envelope()) {
    Ok(_) => ()
    Err(error) => return Err(Trust(error))
  }
  match @trust.verify_root_self(candidate) {
    Ok(_) => ()
    Err(error) => return Err(Trust(error))
  }
  Ok({
    root: candidate,
    // Key rotation can invalidate fast-forwarded timestamp/snapshot state.
    // Drop all cached metadata and require a fresh chain under the new root.
    timestamp: None,
    snapshot: None,
    previous_snapshot: None,
    targets: None,
    update_start: self.update_start,
    budget: self.budget,
    root_rotations: self.root_rotations + 1,
  })
}

///|
/// Intermediate roots may be expired; only the final root is checked against
/// the fixed update start time. Call after the host has no N+1 root to offer.
pub fn Client::finish_root_chain(self : Client) -> Result[Client, ClientError] {
  match self.check_root_fresh() {
    Ok(_) => Ok(self)
    Err(error) => Err(error)
  }
}

///|
pub fn Client::next_root_name(self : Client) -> String? {
  let version = self.root.common().version()
  if version == 2147483647 {
    None
  } else {
    Some((version + 1).to_string() + ".root.json")
  }
}
