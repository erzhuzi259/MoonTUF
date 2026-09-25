///|
/// Match TUF path patterns using shell-style '*' and '?' without crossing '/'.
/// A rolling dynamic-programming row uses O(path length) memory and avoids
/// recursive wildcard backtracking on adversarial patterns.
pub fn path_pattern_matches(pattern : String, path : String) -> Bool {
  let p = @utf8.encode(pattern)
  let t = @utf8.encode(path)
  if p.length() > 1024 || t.length() > 4096 {
    return false
  }
  let mut previous = FixedArray::make(t.length() + 1, false)
  previous[0] = true
  for i in 0..<p.length() {
    let next = FixedArray::make(t.length() + 1, false)
    let token = p[i].to_int()
    if token == 42 {
      next[0] = previous[0]
      for j in 1..<(t.length() + 1) {
        next[j] = previous[j] || (next[j - 1] && t[j - 1].to_int() != 47)
      }
    } else if token == 63 {
      for j in 1..<(t.length() + 1) {
        next[j] = previous[j - 1] && t[j - 1].to_int() != 47
      }
    } else {
      for j in 1..<(t.length() + 1) {
        next[j] = previous[j - 1] && p[i] == t[j - 1]
      }
    }
    previous = next
  }
  previous[t.length()]
}

///|
/// A delegation may use either path patterns or SHA-256 path-hash prefixes.
pub fn DelegatedRole::matches_path(self : DelegatedRole, path : String) -> Bool {
  if self.paths is Some(patterns) {
    for pattern in patterns {
      if path_pattern_matches(pattern, path) {
        return true
      }
    }
    return false
  }
  if self.path_hash_prefixes is Some(prefixes) {
    let digest = @crypto.sha256_hex(@utf8.encode(path))
    for prefix in prefixes {
      if digest.has_prefix(prefix) {
        return true
      }
    }
  }
  false
}
