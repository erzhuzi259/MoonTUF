///|
/// A stream verification result intentionally contains no content: the host
/// owns the temporary file or stream. It must only publish or install that
/// temporary content after finish succeeds.
pub struct VerifiedStream {
  path : String
  length : Int64
  sha256 : String
}

///|
pub fn VerifiedStream::path(self : VerifiedStream) -> String {
  self.path
}

///|
pub fn VerifiedStream::length(self : VerifiedStream) -> Int64 {
  self.length
}

///|
pub fn VerifiedStream::sha256(self : VerifiedStream) -> String {
  self.sha256
}

///|
pub struct TargetStream {
  path : String
  expected_length : Int64
  expected_hashes : Array[(String, String)]
  maximum : Int64
  mut seen : Int64
  mut finished : Bool
  hasher : @sha2.Hasher
  hasher512 : @sha2.Hasher
}

///|
pub fn TargetStream::path(self : TargetStream) -> String {
  self.path
}

///|
pub fn TargetStream::bytes_seen(self : TargetStream) -> Int64 {
  self.seen
}

///|
pub fn TargetStream::remaining(self : TargetStream) -> Int64 {
  self.expected_length - self.seen
}

///|
fn stream_for_descriptor(
  descriptor : @model.TargetFile,
  maximum : Int64,
) -> Result[TargetStream, ClientError] {
  if descriptor.length() > maximum {
    return Err(
      TargetResourceLimit(
        "target:" + descriptor.path(),
        descriptor.length(),
        maximum,
      ),
    )
  }
  Ok({
    path: descriptor.path(),
    expected_length: descriptor.length(),
    expected_hashes: descriptor.hashes(),
    maximum,
    seen: 0L,
    finished: false,
    hasher: @sha2.Hasher::new(kind=@sha2.Sha256),
    hasher512: @sha2.Hasher::new(kind=@sha2.Sha512),
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
  if self.finished {
    return Err(AlreadyFinished)
  }
  let chunk_length = chunk.length().to_int64()
  if chunk_length > self.expected_length - self.seen {
    return Err(
      LengthMismatch(
        "target:" + self.path,
        self.expected_length,
        self.seen + chunk_length,
      ),
    )
  }
  if chunk_length > self.maximum - self.seen {
    return Err(
      TargetResourceLimit(
        "target:" + self.path,
        self.seen + chunk_length,
        self.maximum,
      ),
    )
  }
  self.hasher.write(chunk[:])
  self.hasher512.write(chunk[:])
  self.seen += chunk_length
  Ok(())
}

///|
/// Finalize exactly once. A short stream or incorrect digest fails closed.
pub fn TargetStream::finish(
  self : TargetStream,
) -> Result[VerifiedStream, ClientError] {
  if self.finished {
    return Err(AlreadyFinished)
  }
  self.finished = true
  if self.seen != self.expected_length {
    return Err(
      LengthMismatch("target:" + self.path, self.expected_length, self.seen),
    )
  }
  let digest = self.hasher.finish()
  let computed256 = @crypto.encode_hex(digest)
  let computed512 = @crypto.encode_hex(self.hasher512.finish())
  for (name, expected) in self.expected_hashes {
    let actual = if name == "sha256" { computed256 } else { computed512 }
    if actual != expected {
      return Err(HashMismatch("target:" + self.path))
    }
  }
  Ok({ path: self.path, length: self.seen, sha256: computed256, })
}
