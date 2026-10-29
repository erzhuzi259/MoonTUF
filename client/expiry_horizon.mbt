///|
pub struct RoleDeadline {
  role : String
  version : Int32
  expires : String
  due : Bool
}

///|
pub fn RoleDeadline::role(self : RoleDeadline) -> String {
  self.role
}

///|
pub fn RoleDeadline::version(self : RoleDeadline) -> Int32 {
  self.version
}

///|
pub fn RoleDeadline::expires(self : RoleDeadline) -> String {
  self.expires
}

///|
pub fn RoleDeadline::due(self : RoleDeadline) -> Bool {
  self.due
}

///|
/// Advisory preflight for the FOUR currently accepted top-level roles.
/// Does not advance the trusted clock, authorize future use, extend expiry,
/// or imply anything about unretained delegated metadata expiry.
pub fn Client::expiry_horizon(
  self : Client,
  horizon : String,
) -> Result[Array[RoleDeadline], ClientError] {
  if !@model.valid_utc_time(horizon) {
    return Err(InvalidStartTime(horizon))
  }
  if horizon < self.update_start {
    return Err(ClockRollback(self.update_start, horizon))
  }
  match self.check_complete_fresh() {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let roles = [
    ("root", self.root.common()),
    ("timestamp", self.timestamp.unwrap().common()),
    ("snapshot", self.snapshot.unwrap().common()),
    ("targets", self.targets.unwrap().common()),
  ]
  Ok(
    roles.map(item => {
      role: item.0,
      version: item.1.version(),
      expires: item.1.expires(),
      due: @model.expired(item.1.expires(), horizon),
    }),
  )
}
