///|
/// Host-measured fingerprint of a local cache entry. The library does not
/// verify the underlying cache bytes or follow filesystem paths here.
pub(all) struct CachedTarget {
  path : String
  length : Int64
  sha256 : String
}

///|
pub(all) enum CachePlanError {
  Client(ClientError)
  InvalidCacheEntry(String)
  DuplicateCachedPath(String)
  CacheLimit(Int)
}

///|
pub struct CacheSyncPlan {
  current : Array[String]
  missing : Array[@model.TargetFile]
  changed : Array[@model.TargetFile]
  orphaned : Array[String]
}

///|
pub fn CacheSyncPlan::current(self : CacheSyncPlan) -> Array[String] {
  self.current.copy()
}

///|
pub fn CacheSyncPlan::missing(self : CacheSyncPlan) -> Array[@model.TargetFile] {
  self.missing.copy()
}

///|
pub fn CacheSyncPlan::changed(self : CacheSyncPlan) -> Array[@model.TargetFile] {
  self.changed.copy()
}

///|
pub fn CacheSyncPlan::orphaned(self : CacheSyncPlan) -> Array[String] {
  self.orphaned.copy()
}

///|
fn valid_cache_digest(digest : String) -> Bool {
  if digest.length() != 64 {
    return false
  }
  let bytes = @utf8.encode(digest)
  if bytes.length() != 64 {
    return false
  }
  for byte in bytes {
    let n = byte.to_int()
    if !((n >= 48 && n <= 57) || (n >= 97 && n <= 102)) {
      return false
    }
  }
  true
}

///|
/// Plan downloads against fresh verified top-level descriptors. Orphaned paths
/// are advisory within prefix only, never deletion commands. Downloaded bytes
/// must still pass the client's target verification before installation.
pub fn Client::plan_top_level_sync(
  self : Client,
  cached : Array[CachedTarget],
  prefix? : String = "",
  max_targets? : Int = 1024,
  max_cached? : Int = 4096,
) -> Result[CacheSyncPlan, CachePlanError] {
  let trusted = match
    self.top_level_inventory(prefix~, max_results=max_targets) {
    Err(error) => return Err(Client(error))
    Ok(items) => items
  }
  if max_cached < 0 || cached.length() > max_cached {
    return Err(CacheLimit(max_cached))
  }
  let cache : Map[String, CachedTarget] = Map([])
  for item in cached {
    if item.path.length() > 4096 ||
      !@model.safe_target_path(item.path) ||
      item.length < 0L ||
      !valid_cache_digest(item.sha256) {
      return Err(InvalidCacheEntry(item.path))
    }
    if cache.contains(item.path) {
      return Err(DuplicateCachedPath(item.path))
    }
    cache[item.path] = item
  }
  let paths : Map[String, Bool] = Map([])
  let current : Array[String] = []
  let missing : Array[@model.TargetFile] = []
  let changed : Array[@model.TargetFile] = []
  let orphaned : Array[String] = []
  for target in trusted {
    let path = target.path()
    paths[path] = true
    match cache.get(path) {
      None => missing.push(target)
      Some(item) if item.length == target.length() &&
        item.sha256 == target.sha256() => current.push(path)
      Some(_) => changed.push(target)
    }
  }
  for item in cached {
    if (
        prefix == "" ||
        item.path == prefix ||
        item.path.has_prefix(prefix + "/")
      ) &&
      !paths.contains(item.path) {
      orphaned.push(item.path)
    }
  }
  Ok({ current, missing, changed, orphaned, })
}
