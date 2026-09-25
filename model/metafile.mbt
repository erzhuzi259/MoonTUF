///|
/// A trusted parent metadata document may pin a child to an exact version,
/// length and hash. Optional length/hash fields follow TUF's metadata format.
pub struct MetaFile {
  version : Int
  length : Int?
  sha256 : String?
}

///|
pub fn MetaFile::version(self : MetaFile) -> Int { self.version }

///|
pub fn MetaFile::length(self : MetaFile) -> Int? { self.length }

///|
pub fn MetaFile::sha256(self : MetaFile) -> String? { self.sha256 }

///|
fn sha256_field(raw : @wire.Value, path : String) -> Result[String?, ModelError] {
  let hashes = match raw.field("hashes") {
    None => return Ok(None)
    Some(value) => value
  }
  ignore(match object(hashes, path + ".hashes") {
    Ok(entries) => entries
    Err(error) => return Err(error)
  })
  let digest = match hashes.field("sha256") {
    None => return Err(InvalidValue(path + ".hashes", "SHA-256 is required by this profile"))
    Some(value) =>
      match string(value, path + ".hashes.sha256") {
        Ok(text) => text
        Err(error) => return Err(error)
      }
  }
  let decoded = match @crypto.decode_hex(digest) {
    Ok(bytes) => bytes
    Err(_) => return Err(InvalidValue(path + ".hashes.sha256", "invalid hex digest"))
  }
  if decoded.length() != 32 {
    return Err(InvalidValue(path + ".hashes.sha256", "expected 32-byte digest"))
  }
  Ok(Some(digest))
}

///|
fn meta_file(raw : @wire.Value, path : String) -> Result[MetaFile, ModelError] {
  ignore(match object(raw, path) {
    Ok(entries) => entries
    Err(error) => return Err(error)
  })
  let version = match positive_field(raw, "version", path) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let length = match raw.field("length") {
    None => None
    Some(value) =>
      match nonnegative_int(value, path + ".length") {
        Ok(number) => Some(number)
        Err(error) => return Err(error)
      }
  }
  let sha256 = match sha256_field(raw, path) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  Ok({ version, length, sha256 })
}

///|
pub struct Timestamp {
  envelope : Envelope
  common : Common
  snapshot : MetaFile
}

///|
pub fn Timestamp::envelope(self : Timestamp) -> Envelope { self.envelope }

///|
pub fn Timestamp::common(self : Timestamp) -> Common { self.common }

///|
pub fn Timestamp::snapshot(self : Timestamp) -> MetaFile { self.snapshot }

///|
pub fn parse_timestamp(raw : Bytes, limits? : @wire.Limits = @wire.limits()) -> Result[Timestamp, ModelError] {
  let envelope = match parse_envelope(raw, limits~) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let signed = envelope.signed()
  let common = match parse_common(signed, "timestamp") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let meta = match field(signed, "meta", "signed") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  ignore(match object(meta, "signed.meta") {
    Ok(entries) => entries
    Err(error) => return Err(error)
  })
  let snapshot = match field(meta, "snapshot.json", "signed.meta") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let snapshot = match meta_file(snapshot, "signed.meta.snapshot.json") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  Ok({ envelope, common, snapshot })
}

///|
pub struct Snapshot {
  envelope : Envelope
  common : Common
  meta : Array[(String, MetaFile)]
}

///|
pub fn Snapshot::envelope(self : Snapshot) -> Envelope { self.envelope }

///|
pub fn Snapshot::common(self : Snapshot) -> Common { self.common }

///|
pub fn Snapshot::metafiles(self : Snapshot) -> Array[(String, MetaFile)] { self.meta }

///|
pub fn Snapshot::metafile(self : Snapshot, name : String) -> MetaFile? {
  for entry in self.meta {
    let (candidate, record) = entry
    if candidate == name { return Some(record) }
  }
  None
}

///|
pub fn parse_snapshot(raw : Bytes, limits? : @wire.Limits = @wire.limits()) -> Result[Snapshot, ModelError] {
  let envelope = match parse_envelope(raw, limits~) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let signed = envelope.signed()
  let common = match parse_common(signed, "snapshot") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let raw_meta = match field(signed, "meta", "signed") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let entries = match object(raw_meta, "signed.meta") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let meta : Array[(String, MetaFile)] = []
  let mut has_targets = false
  for entry in entries {
    let (name, raw_child) = entry
    if !safe_metadata_name(name) {
      return Err(InvalidValue("signed.meta." + name, "unsafe metadata path"))
    }
    if name == "targets.json" { has_targets = true }
    let record = match meta_file(raw_child, "signed.meta." + name) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    meta.push((name, record))
  }
  if !has_targets {
    return Err(MissingField("signed.meta.targets.json"))
  }
  Ok({ envelope, common, meta })
}

///|
pub fn safe_metadata_name(name : String) -> Bool {
  let bytes = @utf8.encode(name)
  if bytes.length() < 6 || !name.has_suffix(".json") { return false }
  if bytes[0].to_int() == 47 || bytes[0].to_int() == 92 { return false }
  if name.contains("..") || name.contains("\\") || name.contains(":") { return false }
  for byte in bytes {
    let ch = byte.to_int()
    if ch < 32 || ch == 127 { return false }
  }
  true
}
