///|
/// Metadata conversion failures retain a field path, so a caller can report
/// malformed remote input without treating it as an internal exception.
pub(all) enum ModelError {
  Wire(@wire.WireError)
  MissingField(String)
  WrongType(String)
  InvalidValue(String, String)
  DuplicateItem(String)
  UnsupportedSpec(String)
  InvalidKeyId(String)
} derive(Debug)

///|
pub struct Signature {
  keyid : String
  sig : String
}

///|
pub fn Signature::keyid(self : Signature) -> String { self.keyid }

///|
pub fn Signature::sig(self : Signature) -> String { self.sig }

///|
/// A parsed envelope retains raw bytes for hash-chain checks and the signed
/// value's canonical form for signature verification. These are *different*
/// byte sequences and must never be interchanged.
pub struct Envelope {
  raw : Bytes
  signed : @wire.Value
  canonical_signed : Bytes
  signatures : Array[Signature]
}

///|
pub fn Envelope::raw(self : Envelope) -> Bytes { self.raw }

///|
pub fn Envelope::signed(self : Envelope) -> @wire.Value { self.signed }

///|
pub fn Envelope::canonical_signed(self : Envelope) -> Bytes {
  self.canonical_signed
}

///|
pub fn Envelope::signatures(self : Envelope) -> Array[Signature] {
  self.signatures
}

///|
fn object(value : @wire.Value, path : String) -> Result[Array[(String, @wire.Value)], ModelError] {
  match value.as_dict() {
    Some(entries) => Ok(entries)
    None => Err(WrongType(path))
  }
}

///|
fn array(value : @wire.Value, path : String) -> Result[Array[@wire.Value], ModelError] {
  match value.as_list() {
    Some(entries) => Ok(entries)
    None => Err(WrongType(path))
  }
}

///|
fn field(value : @wire.Value, name : String, parent : String) -> Result[@wire.Value, ModelError] {
  match value.field(name) {
    Some(found) => Ok(found)
    None => Err(MissingField(parent + "." + name))
  }
}

///|
fn string(value : @wire.Value, path : String) -> Result[String, ModelError] {
  match value.as_text() {
    Some(found) => Ok(found)
    None => Err(WrongType(path))
  }
}

///|
fn text_field(value : @wire.Value, name : String, parent : String) -> Result[String, ModelError] {
  let child = match field(value, name, parent) {
    Ok(found) => found
    Err(error) => return Err(error)
  }
  string(child, parent + "." + name)
}

///|
fn positive_int(value : @wire.Value, path : String) -> Result[Int, ModelError] {
  let lexeme = match value.as_integer() {
    Some(number) => number
    None => return Err(WrongType(path))
  }
  let parsed : Int = @string.parse_int(lexeme) catch {
    _ => return Err(InvalidValue(path, "integer exceeds implementation limit"))
  }
  if parsed <= 0 {
    Err(InvalidValue(path, "expected positive integer"))
  } else {
    Ok(parsed)
  }
}

///|
fn nonnegative_int(value : @wire.Value, path : String) -> Result[Int, ModelError] {
  let lexeme = match value.as_integer() {
    Some(number) => number
    None => return Err(WrongType(path))
  }
  let parsed : Int = @string.parse_int(lexeme) catch {
    _ => return Err(InvalidValue(path, "integer exceeds implementation limit"))
  }
  if parsed < 0 {
    Err(InvalidValue(path, "expected nonnegative integer"))
  } else {
    Ok(parsed)
  }
}

///|
fn positive_field(value : @wire.Value, name : String, parent : String) -> Result[Int, ModelError] {
  let child = match field(value, name, parent) {
    Ok(found) => found
    Err(error) => return Err(error)
  }
  positive_int(child, parent + "." + name)
}

///|
fn nonnegative_field(value : @wire.Value, name : String, parent : String) -> Result[Int, ModelError] {
  let child = match field(value, name, parent) {
    Ok(found) => found
    Err(error) => return Err(error)
  }
  nonnegative_int(child, parent + "." + name)
}

///|
fn semver_digit(text : String) -> Bool {
  let bytes = @utf8.encode(text)
  if bytes.length() == 0 { return false }
  if bytes.length() > 1 && bytes[0].to_int() == 48 { return false }
  for byte in bytes {
    let ch = byte.to_int()
    if ch < 48 || ch > 57 { return false }
  }
  true
}

///|
/// Current profile accepts specification major version 1. Other majors may
/// change signed semantics and are rejected rather than guessed at.
fn spec_version(value : @wire.Value) -> Result[String, ModelError] {
  let version = match text_field(value, "spec_version", "signed") {
    Ok(found) => found
    Err(error) => return Err(error)
  }
  let parts : Array[String] = version.split(".").map(part => part.to_owned()).collect()
  if parts.length() != 3 || parts[0] != "1" || !semver_digit(parts[1]) || !semver_digit(parts[2]) {
    Err(UnsupportedSpec(version))
  } else {
    Ok(version)
  }
}

///|
pub struct Common {
  kind : String
  spec_version : String
  version : Int
  expires : String
}

///|
pub fn Common::kind(self : Common) -> String { self.kind }

///|
pub fn Common::version(self : Common) -> Int { self.version }

///|
pub fn Common::expires(self : Common) -> String { self.expires }

///|
pub fn Common::spec_version(self : Common) -> String { self.spec_version }

///|
pub fn parse_common(signed : @wire.Value, kind : String) -> Result[Common, ModelError] {
  let actual_kind = match text_field(signed, "_type", "signed") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  if actual_kind != kind {
    return Err(InvalidValue("signed._type", "expected " + kind))
  }
  let spec = match spec_version(signed) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let version = match positive_field(signed, "version", "signed") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let expires = match text_field(signed, "expires", "signed") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  if !valid_utc_time(expires) {
    return Err(InvalidValue("signed.expires", "expected valid YYYY-MM-DDTHH:MM:SSZ"))
  }
  Ok({ kind: actual_kind, spec_version: spec, version, expires })
}

///|
pub fn parse_envelope(raw : Bytes, limits? : @wire.Limits = @wire.limits()) -> Result[Envelope, ModelError] {
  let parsed = match @wire.parse(raw, limits~) {
    Ok(value) => value
    Err(error) => return Err(Wire(error))
  }
  ignore(match object(parsed, "envelope") {
    Ok(entries) => entries
    Err(error) => return Err(error)
  })
  let signed = match field(parsed, "signed", "envelope") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  ignore(match object(signed, "envelope.signed") {
    Ok(entries) => entries
    Err(error) => return Err(error)
  })
  let raw_signatures = match field(parsed, "signatures", "envelope") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let raw_signatures = match array(raw_signatures, "envelope.signatures") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let signatures : Array[Signature] = []
  let seen : Array[String] = []
  for item in raw_signatures {
    ignore(match object(item, "envelope.signatures[]") {
      Ok(entries) => entries
      Err(error) => return Err(error)
    })
    let keyid = match text_field(item, "keyid", "envelope.signatures[]") {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let sig = match text_field(item, "sig", "envelope.signatures[]") {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    if seen.contains(keyid) {
      return Err(DuplicateItem("envelope.signatures[].keyid=" + keyid))
    }
    seen.push(keyid)
    signatures.push({ keyid, sig })
  }
  Ok({ raw, signed, canonical_signed: @wire.canonical(signed), signatures })
}
