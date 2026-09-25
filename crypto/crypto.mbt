///|
/// Failures at the cryptographic boundary are data errors, not panics. The
/// verifier never falls back to a weaker scheme or accepts an unknown one.
pub(all) enum CryptoError {
  OddHexLength(Int)
  InvalidHexDigit(Int)
  InvalidPublicKeyLength(Int)
  InvalidSignatureLength(Int)
  UnsupportedScheme(String)
} derive(Debug, Eq, Show)

///|
fn nibble(byte : Byte) -> Int? {
  let code = byte.to_int()
  if code >= 48 && code <= 57 {
    Some(code - 48)
  } else if code >= 97 && code <= 102 {
    Some(code - 97 + 10)
  } else if code >= 65 && code <= 70 {
    Some(code - 65 + 10)
  } else {
    None
  }
}

///|
/// Decode a hex string without silently ignoring malformed characters.
pub fn decode_hex(text : String) -> Result[Bytes, CryptoError] {
  let encoded = @utf8.encode(text)
  if encoded.length() % 2 != 0 {
    return Err(OddHexLength(encoded.length()))
  }
  let output : Array[Byte] = []
  let mut cursor = 0
  while cursor < encoded.length() {
    let high = match nibble(encoded[cursor]) {
      Some(value) => value
      None => return Err(InvalidHexDigit(cursor))
    }
    let low = match nibble(encoded[cursor + 1]) {
      Some(value) => value
      None => return Err(InvalidHexDigit(cursor + 1))
    }
    output.push((high * 16 + low).to_byte())
    cursor += 2
  }
  Ok(Bytes::from_array(output))
}

///|
fn hex_char(value : Int) -> Char {
  match value {
    0 => '0'
    1 => '1'
    2 => '2'
    3 => '3'
    4 => '4'
    5 => '5'
    6 => '6'
    7 => '7'
    8 => '8'
    9 => '9'
    10 => 'a'
    11 => 'b'
    12 => 'c'
    13 => 'd'
    14 => 'e'
    _ => 'f'
  }
}

///|
/// Encode bytes in lower-case hex, the representation used by TUF metadata.
pub fn encode_hex(data : Bytes) -> String {
  let builder = StringBuilder()
  for byte in data {
    let code = byte.to_int()
    builder.write_char(hex_char(code >> 4))
    builder.write_char(hex_char(code & 15))
  }
  builder.to_string()
}

///|
pub fn sha256(data : Bytes) -> Bytes {
  @sha2.hash(data[:], kind=@sha2.Sha256)
}

///|
pub fn sha256_hex(data : Bytes) -> String {
  encode_hex(sha256(data))
}

///|
/// Verify an Ed25519 signature using mooncrypt. Only the public key is accepted.
pub fn verify_ed25519(
  public_hex : String,
  message : Bytes,
  signature_hex : String,
) -> Result[Bool, CryptoError] {
  let public_bytes = match decode_hex(public_hex) {
    Ok(bytes) => bytes
    Err(error) => return Err(error)
  }
  if public_bytes.length() != 32 {
    return Err(InvalidPublicKeyLength(public_bytes.length()))
  }
  let signature = match decode_hex(signature_hex) {
    Ok(bytes) => bytes
    Err(error) => return Err(error)
  }
  if signature.length() != 64 {
    return Err(InvalidSignatureLength(signature.length()))
  }
  let key = @ed25519.PublicKey::new(public_bytes[:]) catch {
    _ => return Err(InvalidPublicKeyLength(public_bytes.length()))
  }
  Ok(key.verify(message[:], signature[:]))
}

///|
/// Compare a declared SHA-256 digest against the exact bytes of a candidate.
pub fn matches_sha256(data : Bytes, expected_hex : String) -> Bool {
  let expected = match decode_hex(expected_hex) {
    Ok(bytes) => bytes
    Err(_) => return false
  }
  if expected.length() != 32 {
    return false
  }
  let computed = sha256(data)
  @spec.eq(computed[:], expected[:])
}
