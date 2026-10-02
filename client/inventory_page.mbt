///|
/// One bounded page of verified top-level target descriptors. Delegated
/// targets require separate role resolution and are not included.
pub struct InventoryPage {
  items : Array[@model.TargetFile]
  offset : Int
  total : Int
  next_offset : Int?
}

///|
pub fn InventoryPage::items(self : InventoryPage) -> Array[@model.TargetFile] {
  self.items.copy()
}

///|
pub fn InventoryPage::offset(self : InventoryPage) -> Int {
  self.offset
}

///|
pub fn InventoryPage::total(self : InventoryPage) -> Int {
  self.total
}

///|
pub fn InventoryPage::next_offset(self : InventoryPage) -> Int? {
  self.next_offset
}

///|
/// Page through a trusted top-level namespace without requiring the caller
/// to accept an unbounded result. Offset is measured in matching targets.
pub fn Client::top_level_inventory_page(
  self : Client,
  offset : Int,
  page_size : Int,
  prefix? : String = "",
) -> Result[InventoryPage, ClientError] {
  match self.check_complete_fresh() {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  if prefix != "" && !@model.safe_target_path(prefix) {
    return Err(InvalidPath(prefix))
  }
  if offset < 0 {
    return Err(ResourceLimit("inventory offset", offset, 0))
  }
  if page_size < 1 || page_size > 4096 {
    return Err(ResourceLimit("inventory page size", page_size, 4096))
  }
  let targets = match self.targets {
    Some(value) => value
    None => return Err(MissingStage("targets"))
  }
  let items : Array[@model.TargetFile] = []
  let mut total = 0
  for target in targets.targets() {
    let path = target.path()
    if prefix == "" || path == prefix || path.has_prefix(prefix + "/") {
      if total >= offset && items.length() < page_size {
        items.push(target)
      }
      total = total + 1
    }
  }
  let end = if offset >= total { total } else { offset + items.length() }
  let next_offset = if end < total { Some(end) } else { None }
  Ok({ items, offset, total, next_offset, })
}
