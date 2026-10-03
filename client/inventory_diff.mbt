///|
/// A payload change, comparing length and SHA-256 only, not custom metadata.
pub struct TargetContentChange {
  before : @model.TargetFile
  after : @model.TargetFile
}

///|
pub fn TargetContentChange::before(
  self : TargetContentChange,
) -> @model.TargetFile {
  self.before
}

///|
pub fn TargetContentChange::after(
  self : TargetContentChange,
) -> @model.TargetFile {
  self.after
}

///|
pub struct InventoryDiff {
  added : Array[@model.TargetFile]
  removed : Array[@model.TargetFile]
  changed : Array[TargetContentChange]
  unchanged : Int
}

///|
pub fn InventoryDiff::added(self : InventoryDiff) -> Array[@model.TargetFile] {
  self.added.copy()
}

///|
pub fn InventoryDiff::removed(self : InventoryDiff) -> Array[@model.TargetFile] {
  self.removed.copy()
}

///|
pub fn InventoryDiff::changed(
  self : InventoryDiff,
) -> Array[TargetContentChange] {
  self.changed.copy()
}

///|
pub fn InventoryDiff::unchanged(self : InventoryDiff) -> Int {
  self.unchanged
}

///|
/// Compare two complete, fresh top-level inventories. The host must associate
/// both clients with the same repository; this report is not an update proof,
/// a rollback decision, or delegated metadata authorization.
pub fn Client::diff_top_level_inventory(
  self : Client,
  previous : Client,
  prefix? : String = "",
  max_results? : Int = 1024,
  max_changes? : Int = 2048,
) -> Result[InventoryDiff, ClientError] {
  if max_changes < 0 {
    return Err(ResourceLimit("inventory change budget", 0, max_changes))
  }
  let before = match previous.top_level_inventory(prefix~, max_results~) {
    Err(error) => return Err(error)
    Ok(items) => items
  }
  let after = match self.top_level_inventory(prefix~, max_results~) {
    Err(error) => return Err(error)
    Ok(items) => items
  }
  let old : Map[String, @model.TargetFile] = Map([])
  let current : Map[String, Bool] = Map([])
  for target in before {
    old[target.path()] = target
  }
  let added : Array[@model.TargetFile] = []
  let removed : Array[@model.TargetFile] = []
  let changed : Array[TargetContentChange] = []
  let mut unchanged = 0
  let mut count = 0
  for target in after {
    let path = target.path()
    current[path] = true
    match old.get(path) {
      Some(prior) if prior.length() == target.length() &&
        prior.sha256() == target.sha256() => unchanged += 1
      Some(prior) => {
        if count >= max_changes {
          return Err(ResourceLimit("inventory changes", count + 1, max_changes))
        }
        changed.push({ before: prior, after: target, })
        count += 1
      }
      None => {
        if count >= max_changes {
          return Err(ResourceLimit("inventory changes", count + 1, max_changes))
        }
        added.push(target)
        count += 1
      }
    }
  }
  for target in before {
    if !current.contains(target.path()) {
      if count >= max_changes {
        return Err(ResourceLimit("inventory changes", count + 1, max_changes))
      }
      removed.push(target)
      count += 1
    }
  }
  Ok({ added, removed, changed, unchanged, })
}
