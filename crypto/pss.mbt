///|
/// RFC 8017 EMSA-PSS verification for SHA-256/MGF1-SHA256 and maximum
/// permitted salt length (the TUF/securesystemslib scheme). Also accept the
/// historical digest-size salt used by older repositories.
fn verify_rsa_pss(
  key : @rsa.PublicKey,
  message : Bytes,
  signature : Bytes,
) -> Bool {
  if signature.length() != key.size() {
    return false
  }
  let modulus = BigInt::from_octets(key.modulus()[:])
  let sig = BigInt::from_octets(signature[:])
  if sig >= modulus {
    return false
  }
  let mut bits = 0
  let mut rest = modulus
  while rest > (0 : BigInt) {
    bits += 1
    rest = rest >> 1
  }
  let em_bits = bits - 1
  let em_size = (em_bits + 7) / 8
  let value = sig.pow(BigInt::from_octets(key.exponent()[:]), modulus~)
  if value >= (1 : BigInt) << (8 * em_size) {
    return false
  }
  let encoded = value.to_octets(length=em_size)
  if em_size < 34 || encoded[em_size - 1].to_int() != 188 {
    return false
  }
  let db_size = em_size - 33
  let high_mask = 255 >> (8 * em_size - em_bits)
  if (encoded[0].to_int() & (255 ^ high_mask)) != 0 {
    return false
  }
  let digest = encoded[db_size:em_size - 1].to_owned()
  let db : Array[Byte] = []
  let mut counter = 0
  while db.length() < db_size {
    let input = digest.to_array()
    for
      byte in [
        (counter >> 24).to_byte(),
        (counter >> 16).to_byte(),
        (counter >> 8).to_byte(),
        counter.to_byte(),
      ] {
      input.push(byte)
    }
    for byte in sha256(Bytes::from_array(input)) {
      let i = db.length()
      if i < db_size {
        db.push((encoded[i].to_int() ^ byte.to_int()).to_byte())
      }
    }
    counter += 1
  }
  db[0] = (db[0].to_int() & high_mask).to_byte()
  let mut at = 0
  while at < db_size && db[at].to_int() == 0 {
    at += 1
  }
  if at == db_size || db[at].to_int() != 1 {
    return false
  }
  let salt_size = db_size - at - 1
  if salt_size != 32 && salt_size != em_size - 34 {
    return false
  }
  let primed : Array[Byte] = Array::make(8, (0 : Byte))
  for byte in sha256(message) {
    primed.push(byte)
  }
  for i = at + 1; i < db.length(); i = i + 1 {
    primed.push(db[i])
  }
  @spec.eq(sha256(Bytes::from_array(primed))[:], digest[:])
}
