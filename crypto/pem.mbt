///|
/// Read bounded SPKI PUBLIC KEY PEM. No private-key or certificate coercion.
fn spki(pem : String) -> Array[@asn1.Tlv]? {
  if pem.length() > 16384 {
    return None
  }
  let text = pem.trim().to_owned()
  let begin = "-----BEGIN PUBLIC KEY-----"
  let end = "-----END PUBLIC KEY-----"
  if !text.has_prefix(begin) || !text.has_suffix(end) {
    return None
  }
  let body = text[begin.length():text.length() - end.length()]
  let der = @base64.decode(body, ignore_whitespace=true) catch {
    _ => return None
  }
  let outer = @asn1.only(der[:]) catch { _ => return None }
  if outer.tag != 48 {
    return None
  }
  let parts = outer.items() catch { _ => return None }
  if parts.length() != 2 || parts[0].tag != 48 || parts[1].tag != 3 {
    return None
  }
  Some(parts)
}

///|
fn rsa_key(pem : String) -> @rsa.PublicKey? {
  let parts = match spki(pem) {
    Some(value) => value
    None => return None
  }
  let algorithm = parts[0].items() catch { _ => return None }
  if algorithm.length() != 2 {
    return None
  }
  let oid = algorithm[0].oid() catch { _ => return None }
  if oid != "1.2.840.113549.1.1.1" ||
    algorithm[1].tag != 5 ||
    algorithm[1].value.length() != 0 {
    return None
  }
  let bits = parts[1].bits() catch { _ => return None }
  if bits.unused != 0 {
    return None
  }
  let encoded = @asn1.only(bits.bytes[:]) catch { _ => return None }
  if encoded.tag != 48 {
    return None
  }
  let numbers = encoded.items() catch { _ => return None }
  if numbers.length() != 2 {
    return None
  }
  let n = numbers[0].int() catch { _ => return None }
  let e = numbers[1].int() catch { _ => return None }
  // Bound public exponent work as well as modulus width. Values outside this
  // interoperability policy fail closed rather than doing unbounded exponentiation.
  if n < (1 : BigInt) << 2047 ||
    n >= (1 : BigInt) << 8192 ||
    (n & (1 : BigInt)) == (0 : BigInt) ||
    e < (3 : BigInt) ||
    e > (2147483647 : BigInt) ||
    (e & (1 : BigInt)) == (0 : BigInt) {
    return None
  }
  // mooncrypt's PSS verifier assumes a modulus whose bit length is byte-aligned.
  // Validate EMSA-PSS here with the actual modulus bit count instead.
  let key = @rsa.PublicKey::new(
    n.to_octets()[:],
    e.to_octets()[:],
    scheme=@rsa.Pss(salt=32),
  ) catch {
    _ => return None
  }
  Some(key)
}

///|
fn ecdsa_key(pem : String) -> @ecdsa.PublicKey? {
  let parts = match spki(pem) {
    Some(value) => value
    None => return None
  }
  let algorithm = parts[0].items() catch { _ => return None }
  if algorithm.length() != 2 {
    return None
  }
  let oid = algorithm[0].oid() catch { _ => return None }
  let curve = algorithm[1].oid() catch { _ => return None }
  if oid != "1.2.840.10045.2.1" || curve != "1.2.840.10045.3.1.7" {
    return None
  }
  let bits = parts[1].bits() catch { _ => return None }
  if bits.unused != 0 {
    return None
  }
  let key = @ecdsa.PublicKey::new(bits.bytes[:]) catch { _ => return None }
  Some(key)
}

///|
fn ecdsa_signature(der : Bytes) -> Bytes? {
  if der.length() > 72 {
    return None
  }
  let outer = @asn1.only(der[:]) catch { _ => return None }
  if outer.tag != 48 {
    return None
  }
  let numbers = outer.items() catch { _ => return None }
  if numbers.length() != 2 {
    return None
  }
  let r = numbers[0].int() catch { _ => return None }
  let s = numbers[1].int() catch { _ => return None }
  if r <= (0 : BigInt) ||
    s <= (0 : BigInt) ||
    r >= (1 : BigInt) << 256 ||
    s >= (1 : BigInt) << 256 {
    return None
  }
  let bytes = r.to_octets(length=32).to_array()
  for byte in s.to_octets(length=32) {
    bytes.push(byte)
  }
  Some(Bytes::from_array(bytes))
}

///|
/// Supported algorithms are explicit: unknown schemes never weaken a threshold.
pub fn valid_public_key(
  keytype : String,
  scheme : String,
  public : String,
) -> Bool {
  match (keytype, scheme) {
    ("ed25519", "ed25519") =>
      match decode_hex(public) {
        Ok(bytes) => bytes.length() == 32
        _ => false
      }
    ("rsa", "rsassa-pss-sha256") => rsa_key(public) is Some(_)
    ("ecdsa", "ecdsa-sha2-nistp256") => ecdsa_key(public) is Some(_)
    _ => false
  }
}

///|
pub fn verify_signature(
  keytype : String,
  scheme : String,
  public : String,
  message : Bytes,
  signature_hex : String,
) -> Result[Bool, CryptoError] {
  if keytype == "ed25519" && scheme == "ed25519" {
    return verify_ed25519(public, message, signature_hex)
  }
  let signature = match decode_hex(signature_hex) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  match (keytype, scheme) {
    ("rsa", "rsassa-pss-sha256") =>
      match rsa_key(public) {
        Some(key) => Ok(verify_rsa_pss(key, message, signature))
        None => Err(InvalidPublicKeyLength(public.length()))
      }
    ("ecdsa", "ecdsa-sha2-nistp256") =>
      match (ecdsa_key(public), ecdsa_signature(signature)) {
        (Some(key), Some(sig)) => Ok(key.verify(message[:], sig[:]))
        _ => Ok(false)
      }
    _ => Err(UnsupportedScheme(scheme))
  }
}
