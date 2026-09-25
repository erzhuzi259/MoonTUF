///|
/// A verified target is an authentic byte sequence for a requested path.
/// Authenticity does not imply that executing or installing it is safe.
pub struct VerifiedTarget {
  path : String
  bytes : Bytes
  sha256 : String
}

///|
pub fn VerifiedTarget::path(self : VerifiedTarget) -> String {
  self.path
}

///|
pub fn VerifiedTarget::bytes(self : VerifiedTarget) -> Bytes {
  self.bytes
}

///|
pub fn VerifiedTarget::sha256(self : VerifiedTarget) -> String {
  self.sha256
}

///|
pub fn VerifiedTarget::length(self : VerifiedTarget) -> Int64 {
  self.bytes.length().to_int64()
}

///|
/// Verify exact target length and SHA-256 before returning a VerifiedTarget.
/// The host must bound reads before passing candidate bytes to this function.
pub fn Client::verify_top_level_target(
  self : Client,
  path : String,
  candidate : Bytes,
) -> Result[VerifiedTarget, ClientError] {
  let descriptor = match self.top_level_target(path) {
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
/// Compute the expected target repository filename. With consistent
/// snapshots, the trusted content hash prefixes only the basename.
pub fn Client::top_level_target_request_name(
  self : Client,
  path : String,
) -> Result[String, ClientError] {
  let descriptor = match self.top_level_target(path) {
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
  let basename = parts[parts.length() - 1]
  let mut result = descriptor.sha256() + "." + basename
  let mut index = parts.length() - 2
  while index >= 0 {
    result = parts[index] + "/" + result
    index -= 1
  }
  Ok(result)
}
