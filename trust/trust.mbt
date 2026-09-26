///|
pub(all) enum TrustError {
  UnknownRole(String)
  InvalidThreshold(Int, Int)
  ThresholdNotMet(String, Int, Int)
  MalformedSignature(String)
  UnsupportedKey(String)
} derive(Debug)

///|
fn contains_sorted_keyid(keys : Array[String], keyid : String) -> Bool {
  let mut first = 0
  let mut end = keys.length()
  while first < end {
    let middle = first + (end - first) / 2
    if keys[middle] < keyid {
      first = middle + 1
    } else {
      end = middle
    }
  }
  first < keys.length() && keys[first] == keyid
}

///|
fn find_sorted_key(
  keys : Array[@model.PublicKey],
  keyid : String,
) -> @model.PublicKey? {
  let mut first = 0
  let mut end = keys.length()
  while first < end {
    let middle = first + (end - first) / 2
    if keys[middle].keyid() < keyid {
      first = middle + 1
    } else {
      end = middle
    }
  }
  if first < keys.length() && keys[first].keyid() == keyid {
    Some(keys[first])
  } else {
    None
  }
}

///|
/// Count only distinct, authorized, correctly verified signers. The envelope
/// parser rejects duplicate key IDs before this function is called. Sorted
/// indices prevent linear scans for every untrusted signature.
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
  let authorized = keyids.copy()
  authorized.sort()
  let key_index = keys.copy()
  key_index.sort_by(fn(left, right) {
    if left.keyid() < right.keyid() {
      -1
    } else if left.keyid() > right.keyid() {
      1
    } else {
      0
    }
  })
  let signed = envelope.canonical_signed()
  let mut valid = 0
  for signature in envelope.signatures() {
    let id = signature.keyid()
    if !contains_sorted_keyid(authorized, id) {
      continue
    }
    let key = match find_sorted_key(key_index, id) {
      Some(value) => value
      None => return Err(UnsupportedKey(id))
    }
    let verified = match
      @crypto.verify_ed25519(key.public_hex(), signed, signature.sig()) {
      Ok(value) => value
      Err(_) => return Err(MalformedSignature(id))
    }
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
