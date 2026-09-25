///|
/// A stream verification result intentionally contains no content: the host
/// owns the temporary file or stream. It must only publish or install that
/// temporary content after finish succeeds.
pub struct VerifiedStream {
  path : String
  length : Int
  sha256 : String
}

///|
pub fn VerifiedStream::path(self : VerifiedStream) -> String { self.path }

///|
pub fn VerifiedStream::length(self : VerifiedStream) -> Int { self.length }

///|
pub fn VerifiedStream::sha256(self : VerifiedStream) -> String { self.sha256 }

///|
pub struct TargetStream {
  path : String
  expected_length : Int
  expected_sha256 : String
  maximum : Int
  mut seen : Int
  mut finished : Bool
  hasher : @sha2.Hasher
}

///|
pub fn TargetStream::path(self : TargetStream) -> String { self.path }

///|
pub fn TargetStream::bytes_seen(self : TargetStream) -> Int { self.seen }

///|
pub fn TargetStream::remaining(self : TargetStream) -> Int {
  self.expected_length - self.seen
}

///|
fn stream_for_descriptor(
  descriptor : @model.TargetFile,
  maximum : Int,
) -> Result[TargetStream, ClientError] {
  if descriptor.length() > maximum {
    return Err(ResourceLimit("target:" + descriptor.path(), descriptor.length(), maximum))
  }
  Ok({
    path: descriptor.path(),
    expected_length: descriptor.length(),
    expected_sha256: descriptor.sha256(),
    maximum,
    seen: 0,
    finished: false,
    hasher: @sha2.Hasher::new(kind=@sha2.Sha256),
  })
}

///|
/// Start streaming verification for a top-level target without loading the
/// whole target into MoonBit memory.
pub fn Client::open_top_level_stream(
  self : Client,
  path : String,
) -> Result[TargetStream, ClientError] {
  let descriptor = match self.top_level_target(path) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  stream_for_descriptor(descriptor, self.budget.max_target_bytes)
}

///|
/// Start streaming verification for a target found in a verified delegated
/// role. The loader is queried only for matching delegated metadata.
pub fn Client::open_stream(
  self : Client,
  path : String,
  load : (String) -> Bytes?,
) -> Result[TargetStream, ClientError] {
  let descriptor = match self.find_target(path, load) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  stream_for_descriptor(descriptor, self.budget.max_target_bytes)
}

///|
/// Hash one bounded chunk. A chunk that would exceed the target's exact
/// declared length is rejected before modifying the stream state.
pub fn TargetStream::write(
  self : TargetStream,
  chunk : Bytes,
) -> Result[Unit, ClientError] {
  if self.finished { return Err(AlreadyFinished) }
  if chunk.length() > self.expected_length - self.seen {
    return Err(LengthMismatch(
      self.path,
      self.expected_length,
      self.seen + chunk.length(),
    ))
  }
  if chunk.length() > self.maximum - self.seen {
    return Err(ResourceLimit(
      "target:" + self.path,
      self.seen + chunk.length(),
      self.maximum,
    ))
  }
  self.hasher.write(chunk[:])
  self.seen += chunk.length()
  Ok(())
}

///|
/// Finalize exactly once. A short stream or incorrect digest fails closed.
pub fn TargetStream::finish(
  self : TargetStream,
) -> Result[VerifiedStream, ClientError] {
  if self.finished { return Err(AlreadyFinished) }
  self.finished = true
  if self.seen != self.expected_length {
    return Err(LengthMismatch(self.path, self.expected_length, self.seen))
  }
  let digest = self.hasher.finish()
  let expected = match @crypto.decode_hex(self.expected_sha256) {
    Ok(value) => value
    Err(_) => return Err(HashMismatch(self.path))
  }
  if !@spec.eq(digest[:], expected[:]) {
    return Err(HashMismatch(self.path))
  }
  Ok({
    path: self.path,
    length: self.seen,
    sha256: self.expected_sha256,
  })
}
