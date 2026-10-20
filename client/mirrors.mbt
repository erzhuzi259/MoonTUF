///|
pub(all) enum MirrorStatus {
  Unavailable
  Rejected(ClientError)
  Verified
} derive(Debug)

///|
pub extend MirrorStatus with @debug.Debug::{to_repr}

///|
pub struct MirrorAttempt {
  mirror : String
  status : MirrorStatus
}

///|
pub fn MirrorAttempt::mirror(self : MirrorAttempt) -> String {
  self.mirror
}

///|
pub fn MirrorAttempt::status(self : MirrorAttempt) -> MirrorStatus {
  self.status
}

///|
pub struct MirrorDownload {
  target : VerifiedTarget?
  attempts : Array[MirrorAttempt]
}

///|
pub fn MirrorDownload::target(self : MirrorDownload) -> VerifiedTarget? {
  self.target
}

///|
pub fn MirrorDownload::attempts(self : MirrorDownload) -> Array[MirrorAttempt] {
  self.attempts.copy()
}

///|
/// Resolve ONE trusted descriptor before trying any host-approved mirrors.
/// Invalid bytes do not change trust, version pins, algorithms or role order.
/// The loader must bound reads to the supplied length; nothing is installed.
pub fn Client::download_from_mirrors(
  self : Client,
  path : String,
  mirrors : Array[String],
  load_metadata : (String) -> Bytes?,
  fetch : (String, String, Int64) -> Bytes?,
  max_mirrors~ : Int32 = 8,
) -> Result[MirrorDownload, ClientError] {
  if max_mirrors < 1 ||
    max_mirrors > 32 ||
    mirrors.is_empty() ||
    mirrors.length() > max_mirrors {
    return Err(ResourceLimit("mirrors", mirrors.length(), max_mirrors))
  }
  let ids : Map[String, Bool] = Map([])
  for mirror in mirrors {
    if mirror.is_empty() || mirror.length() > 4096 || ids.contains(mirror) {
      return Err(InvalidPath("mirror identifier"))
    }
    ids[mirror] = true
  }
  let descriptor = match self.find_target(path, load_metadata) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  if descriptor.length() > self.budget.max_target_bytes {
    return Err(
      TargetResourceLimit(
        path,
        descriptor.length(),
        self.budget.max_target_bytes,
      ),
    )
  }
  let name = self.descriptor_request_name(descriptor)
  let attempts : Array[MirrorAttempt] = []
  for mirror in mirrors {
    let candidate = match fetch(mirror, name, descriptor.length()) {
      Some(bytes) => bytes
      None => {
        attempts.push({ mirror, status: Unavailable, })
        continue
      }
    }
    if candidate.length().to_int64() != descriptor.length() {
      attempts.push({
        mirror,
        status: Rejected(
          LengthMismatch(
            path,
            descriptor.length(),
            candidate.length().to_int64(),
          ),
        ),
      })
      continue
    }
    if !@crypto.matches_hashes(candidate, descriptor.hashes()) {
      attempts.push({ mirror, status: Rejected(HashMismatch(path)), })
      continue
    }
    attempts.push({ mirror, status: Verified, })
    return Ok({
      target: Some({
        path,
        bytes: candidate,
        sha256: @crypto.sha256_hex(candidate),
      }),
      attempts,
    })
  }
  Ok({ target: None, attempts, })
}
