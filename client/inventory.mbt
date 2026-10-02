///|
/// Enumerate verified top-level target descriptors under one path namespace.
/// Delegated targets are deliberately excluded: they require role-specific
/// metadata resolution and must not be inferred from this inventory.
/// The result is all-or-error when `max_results` is exceeded.
pub fn Client::top_level_inventory(
  self : Client,
  prefix? : String = "",
  max_results? : Int = 1024,
) -> Result[Array[@model.TargetFile], ClientError] {
  match self.check_complete_fresh() {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  if prefix != "" && !@model.safe_target_path(prefix) {
    return Err(InvalidPath(prefix))
  }
  if max_results < 1 {
    return Err(ResourceLimit("inventory results", 1, max_results))
  }
  let targets = match self.targets {
    Some(value) => value
    None => return Err(MissingStage("targets"))
  }
  let selected : Array[@model.TargetFile] = []
  for target in targets.targets() {
    let path = target.path()
    if prefix == "" || path == prefix || path.has_prefix(prefix + "/") {
      if selected.length() >= max_results {
        return Err(
          ResourceLimit("inventory results", selected.length() + 1, max_results),
        )
      }
      selected.push(target)
    }
  }
  Ok(selected)
}
