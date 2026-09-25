///|
pub(all) enum TrustError {
  UnknownRole(String)
  InvalidThreshold(Int, Int)
  ThresholdNotMet(String, Int, Int)
  MalformedSignature(String)
  UnsupportedKey(String)
} derive(Debug)

///|
fn find_key(
  keys : Array[@model.PublicKey],
  keyid : String,
) -> @model.PublicKey? {
  for key in keys {
    if key.keyid() == keyid {
      return Some(key)
    }
  }
  None
}

///|
/// Count only distinct, authorized, correctly verified signers. The envelope
/// parser rejects duplicate key IDs before this function is called.
pub fn verify_threshold(
  envelope : @model.Envelope,
  keys : Array[@model.PublicKey],
  keyids : Array[String],
  threshold : Int,
  role_name : String,
) -> Result[Int, TrustError] {
  if threshold < 1 || threshold > keyids.length() {
    return Err(InvalidThreshold(threshold, keyids.length()))
  }
  let signed = envelope.canonical_signed()
  let mut valid = 0
  let seen : Array[String] = []
  for signature in envelope.signatures() {
    let id = signature.keyid()
    if !keyids.contains(id) || seen.contains(id) {
      continue
    }
    let key = match find_key(keys, id) {
      Some(value) => value
      None => return Err(UnsupportedKey(id))
    }
    let verified = match
      @crypto.verify_ed25519(key.public_hex(), signed, signature.sig()) {
      Ok(value) => value
      Err(_) => return Err(MalformedSignature(id))
    }
    seen.push(id)
    if verified {
      valid += 1
    }
  }
  if valid < threshold {
    Err(ThresholdNotMet(role_name, valid, threshold))
  } else {
    Ok(valid)
  }
}

///|
pub fn verify_top_level(
  root : @model.Root,
  role_name : String,
  envelope : @model.Envelope,
) -> Result[Int, TrustError] {
  let role = match root.role(role_name) {
    Some(value) => value
    None => return Err(UnknownRole(role_name))
  }
  verify_threshold(
    envelope,
    root.keys(),
    role.keyids(),
    role.threshold(),
    role_name,
  )
}

///|
/// A root must be self-signed even when its bytes are distributed through an
/// out-of-band trusted bootstrap channel. Self-signing does not establish that
/// bootstrap trust; the embedding application must authenticate the anchor.
pub fn verify_root_self(root : @model.Root) -> Result[Int, TrustError] {
  verify_top_level(root, "root", root.envelope())
}

///|
pub fn verify_delegated(
  parent : @model.Delegations,
  role : @model.DelegatedRole,
  envelope : @model.Envelope,
) -> Result[Int, TrustError] {
  verify_threshold(
    envelope,
    parent.keys(),
    role.keyids(),
    role.threshold(),
    role.name(),
  )
}
