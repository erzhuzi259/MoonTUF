///|
/// Python fnmatchcase-style classes; ! negates and '/' is ordinary.
fn class_match(
  pattern : Array[Char],
  start : Int32,
  candidate : Char,
) -> (Int32, Bool)? {
  let mut end = start + 1
  let negative = end < pattern.length() && pattern[end] == '!'
  if negative {
    end += 1
  }
  let content = end
  if end < pattern.length() && pattern[end] == ']' {
    end += 1
  }
  while end < pattern.length() && pattern[end] != ']' {
    end += 1
  }
  if end >= pattern.length() {
    return None
  }
  let mut found = false
  let mut i = content
  while i < end {
    if i + 2 < end && pattern[i + 1] == '-' {
      if pattern[i] <= candidate && candidate <= pattern[i + 2] {
        found = true
      }
      i += 3
    } else {
      if pattern[i] == candidate {
        found = true
      }
      i += 1
    }
  }
  Some((end + 1, if negative { !found } else { found }))
}

///|
/// Rolling Unicode DP avoids exponential wildcard backtracking.
pub fn path_pattern_matches(pattern : String, path : String) -> Bool {
  if @utf8.encode(pattern).length() > 1024 || @utf8.encode(path).length() > 4096 {
    return false
  }
  let p : Array[Char] = pattern.iter().collect()
  let t : Array[Char] = path.iter().collect()
  let mut row = FixedArray::make(t.length() + 1, false)
  row[0] = true
  let mut i = 0
  while i < p.length() {
    let next = FixedArray::make(t.length() + 1, false)
    if p[i] == '*' {
      next[0] = row[0]
      for j = 1; j <= t.length(); j = j + 1 {
        next[j] = row[j] || next[j - 1]
      }
      i += 1
    } else {
      let mut next_i = i + 1
      for j = 1; j <= t.length(); j = j + 1 {
        let matched = if p[i] == '?' {
          true
        } else if p[i] == '[' {
          match class_match(p, i, t[j - 1]) {
            Some((end, matched)) => {
              next_i = end
              matched
            }
            None => t[j - 1] == '['
          }
        } else {
          p[i] == t[j - 1]
        }
        next[j] = row[j - 1] && matched
      }
      i = next_i
    }
    row = next
  }
  row[t.length()]
}

///|
pub fn DelegatedRole::matches_path(self : DelegatedRole, path : String) -> Bool {
  if self.paths is Some(patterns) {
    return patterns.any(fn(pattern) { path_pattern_matches(pattern, path) })
  }
  if self.path_hash_prefixes is Some(prefixes) {
    let digest = @crypto.sha256_hex(@utf8.encode(path))
    return prefixes.any(fn(prefix) { digest.has_prefix(prefix) })
  }
  false
}
