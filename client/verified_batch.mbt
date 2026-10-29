///|
pub struct VerifiedBatch {
  priv targets : Array[VerifiedTarget]
  length : Int64
  root_sha256 : String
  snapshot_version : Int32
}

///|
pub fn VerifiedBatch::targets(self : VerifiedBatch) -> Array[VerifiedTarget] {
  self.targets.copy()
}

///|
pub fn VerifiedBatch::length(self : VerifiedBatch) -> Int64 {
  self.length
}

///|
pub fn VerifiedBatch::root_sha256(self : VerifiedBatch) -> String {
  self.root_sha256
}

///|
pub fn VerifiedBatch::snapshot_version(self : VerifiedBatch) -> Int32 {
  self.snapshot_version
}

///|
/// All-or-error verification of explicit target bytes under one fresh client.
/// Preflight total bytes and duplicate paths BEFORE loading delegated metadata.
/// Resolution caches raw metadata but rechecks each target's authorization.
/// No partial VerifiedBatch escapes; atomic installation remains a host task.
pub fn Client::verify_batch(
  self : Client,
  candidates : Array[(String, Bytes)],
  load : (String) -> Bytes?,
  max_targets~ : Int32 = 256,
  max_total_bytes~ : Int64 = 268435456L,
) -> Result[VerifiedBatch, ClientError] {
  match self.check_complete_fresh() {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  if max_targets < 0 || max_targets > 1024 || candidates.length() > max_targets {
    return Err(
      ResourceLimit("verified batch targets", candidates.length(), max_targets),
    )
  }
  if max_total_bytes < 0L || max_total_bytes > 1L << 40 {
    return Err(TargetResourceLimit("verified batch limit", 0L, max_total_bytes))
  }
  let paths : Array[String] = []
  let seen : Map[String, Bool] = Map([])
  let mut total = 0L
  for (path, bytes) in candidates {
    if !@model.safe_target_path(path) || seen.contains(path) {
      return Err(InvalidPath(path))
    }
    seen[path] = true
    let length = bytes.length().to_int64()
    if length > self.budget.max_target_bytes {
      return Err(
        TargetResourceLimit(path, length, self.budget.max_target_bytes),
      )
    }
    if length > max_total_bytes - total {
      return Err(
        TargetResourceLimit(
          "verified batch bytes",
          total + length,
          max_total_bytes,
        ),
      )
    }
    total += length
    paths.push(path)
  }
  let plan = match
    self.resolve_plan(
      paths,
      load,
      max_targets~,
      max_metadata=self.budget.max_delegated_roles,
    ) {
    Err(e) => return Err(e)
    Ok(p) => p
  }
  let output : Array[VerifiedTarget] = []
  for i, planned in plan.targets {
    let (path, bytes) = candidates[i]
    let descriptor = planned.resolution.descriptor()
    if bytes.length().to_int64() != descriptor.length() {
      return Err(
        LengthMismatch(path, descriptor.length(), bytes.length().to_int64()),
      )
    }
    if !@crypto.matches_hashes(bytes, descriptor.hashes()) {
      return Err(HashMismatch(path))
    }
    output.push({ path, bytes, sha256: @crypto.sha256_hex(bytes), })
  }
  Ok({
    targets: output,
    length: total,
    root_sha256: plan.root_sha256,
    snapshot_version: plan.snapshot_version,
  })
}
