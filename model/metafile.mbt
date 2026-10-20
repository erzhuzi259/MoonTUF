///|
/// A trusted parent metadata document may pin a child to an exact version,
/// length and hash. Optional length/hash fields follow TUF's metadata format.
pub struct MetaFile {
  version : Int32
  length : Int32?
  hashes : Array[(String, String)]
  sha256 : String?
}

///|
pub fn MetaFile::version(self : MetaFile) -> Int32 {
  self.version
}

///|
pub fn MetaFile::length(self : MetaFile) -> Int32? {
  self.length
}

///|
pub fn MetaFile::hashes(self : MetaFile) -> Array[(String, String)] {
  self.hashes.copy()
}

///|
pub fn MetaFile::preferred_hash(self : MetaFile) -> (String, String) {
  match hash_value(self.hashes, "sha256") {
    Some(value) => ("sha256", value)
    None => ("sha512", hash_value(self.hashes, "sha512").unwrap_or(""))
  }
}

///|
pub fn MetaFile::sha256(self : MetaFile) -> String? {
  self.sha256
}

///|
fn hash_value(hashes : Array[(String, String)], name : String) -> String? {
  for (algorithm, digest) in hashes {
    if name == algorithm {
      return Some(digest)
    }
  }
  None
}

///|
fn read_hashes(
  raw : @wire.Value,
  path : String,
  required : Bool,
) -> Result[Array[(String, String)], ModelError] {
  let value = match raw.field("hashes") {
    Some(value) => value
    None =>
      if required {
        return Err(MissingField(path + ".hashes"))
      } else {
        return Ok([])
      }
  }
  let fields = match object(value, path + ".hashes") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let hashes : Array[(String, String)] = []
  for (name, value) in fields {
    let digest = match string(value, path + ".hashes." + name) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let bytes = match @crypto.decode_hex(digest) {
      Ok(value) => value
      Err(_) => return Err(InvalidValue(path, "invalid digest"))
    }
    let size = if name == "sha256" {
      32
    } else if name == "sha512" {
      64
    } else {
      0
    }
    if size > 0 {
      if bytes.length() != size {
        return Err(InvalidValue(path, "wrong digest length"))
      }
      hashes.push((name, @crypto.encode_hex(bytes)))
    }
  }
  // If hashes were supplied, at least one must be supported. Never silently
  // treat an unsupported-only hash list as an unpinned metadata descriptor.
  if hashes.is_empty() {
    return Err(InvalidValue(path, "no supported hashes"))
  }
  hashes.sort_by(fn(a, b) { a.0.lexical_compare(b.0) })
  Ok(hashes)
}

///|
fn meta_file(raw : @wire.Value, path : String) -> Result[MetaFile, ModelError] {
  ignore(
    match object(raw, path) {
      Ok(entries) => entries
      Err(error) => return Err(error)
    },
  )
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
  let hashes = match read_hashes(raw, path, false) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  Ok({ version, length, sha256: hash_value(hashes, "sha256"), hashes, })
}

///|
pub struct Timestamp {
  envelope : Envelope
  common : Common
  snapshot : MetaFile
}

///|
pub fn Timestamp::envelope(self : Timestamp) -> Envelope {
  self.envelope
}

///|
pub fn Timestamp::common(self : Timestamp) -> Common {
  self.common
}

///|
pub fn Timestamp::snapshot(self : Timestamp) -> MetaFile {
  self.snapshot
}

///|
pub fn parse_timestamp(
  raw : Bytes,
  limits~ : @wire.Limits = @wire.limits(),
) -> Result[Timestamp, ModelError] {
  let envelope = match parse_envelope(raw, limits~) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let signed = envelope.signed
  let common = match parse_common(signed, "timestamp") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let meta = match field(signed, "meta", "signed") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let entries = match object(meta, "signed.meta") {
    Ok(entries) => entries
    Err(error) => return Err(error)
  }
  if entries.length() != 1 {
    return Err(
      InvalidValue("signed.meta", "timestamp may describe only snapshot.json"),
    )
  }
  let snapshot = match field(meta, "snapshot.json", "signed.meta") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let snapshot = match meta_file(snapshot, "signed.meta.snapshot.json") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  Ok({ envelope, common, snapshot, })
}

///|
pub struct Snapshot {
  envelope : Envelope
  common : Common
  meta : Array[(String, MetaFile)]
}

///|
pub fn Snapshot::envelope(self : Snapshot) -> Envelope {
  self.envelope
}

///|
pub fn Snapshot::common(self : Snapshot) -> Common {
  self.common
}

///|
pub fn Snapshot::metafiles(self : Snapshot) -> Array[(String, MetaFile)] {
  self.meta.copy()
}

///|
pub fn Snapshot::metafile(self : Snapshot, name : String) -> MetaFile? {
  for entry in self.meta {
    let (candidate, record) = entry
    if candidate == name {
      return Some(record)
    }
  }
  None
}

///|
pub fn parse_snapshot(
  raw : Bytes,
  limits~ : @wire.Limits = @wire.limits(),
) -> Result[Snapshot, ModelError] {
  let envelope = match parse_envelope(raw, limits~) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let signed = envelope.signed
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
    if name == "targets.json" {
      has_targets = true
    }
    let record = match meta_file(raw_child, "signed.meta." + name) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    meta.push((name, record))
  }
  if !has_targets {
    return Err(MissingField("signed.meta.targets.json"))
  }
  Ok({ envelope, common, meta, })
}

///|
pub fn safe_metadata_name(name : String) -> Bool {
  name.has_suffix(".json") &&
  safe_role_name(name[0:name.length() - 5].to_owned())
}

///|
/// Role names are opaque URL components, NOT filesystem paths. Adapters must
/// percent-encode the whole name (including slashes) before network access.
pub fn safe_role_name(name : String) -> Bool {
  if name.is_empty() || @utf8.encode(name).length() > 4096 {
    return false
  }
  for ch in name.iter() {
    if ch.to_int() < 32 || ch.to_int() == 127 {
      return false
    }
  }
  true
}
