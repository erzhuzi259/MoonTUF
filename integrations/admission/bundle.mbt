///|
/// Multi-artifact updates are common for plugins, firmware and model bundles.
/// This planner validates every requested target under one trusted metadata
/// snapshot before the host starts downloading any of them.
pub struct BundlePolicy {
  artifact_policy : Policy
  max_files : Int
  max_total_bytes : Int64
}

///|
pub fn bundle_policy(
  artifact_policy : Policy,
  max_files? : Int = 16,
  max_total_bytes? : Int64 = 1024L * 1024L * 1024L,
) -> Result[BundlePolicy, AdmissionError] {
  if max_files < 1 || max_files > 1024 {
    return Err(InvalidPolicy("max_files must be between 1 and 1024"))
  }
  if max_total_bytes < 1L {
    return Err(InvalidPolicy("max_total_bytes must be positive"))
  }
  Ok({ artifact_policy, max_files, max_total_bytes, })
}

///|
pub(all) enum BundleError {
  Admission(AdmissionError)
  EmptyBundle
  DuplicatePath(String)
  TooManyFiles(Int, Int)
  TotalTooLarge(Int64, Int64)
  WrongCandidateCount(Int, Int)
  StreamOrder(Int, Int)
  BundleIncomplete(Int, Int)
  SessionClosed
} derive(Debug)

///|
pub struct BundlePlan {
  tickets : Array[Ticket]
  current_paths : Array[String]
  total_bytes : Int64
  root_version : Int
  snapshot_version : Int
}

///|
pub fn BundlePlan::tickets(self : BundlePlan) -> Array[Ticket] {
  self.tickets.copy()
}

///|
pub fn BundlePlan::current_paths(self : BundlePlan) -> Array[String] {
  self.current_paths.copy()
}

///|
pub fn BundlePlan::total_bytes(self : BundlePlan) -> Int64 {
  self.total_bytes
}

///|
pub fn BundlePlan::root_version(self : BundlePlan) -> Int {
  self.root_version
}

///|
pub fn BundlePlan::snapshot_version(self : BundlePlan) -> Int {
  self.snapshot_version
}

///|
/// Installed hashes are supplied as (path, hex digest) pairs. A path without
/// an installed hash is treated as absent. A plan can mix current files and
/// files to download; the caller chooses an atomic staging/commit mechanism.
pub fn plan_bundle(
  client : @client.Client,
  paths : Array[String],
  policy : BundlePolicy,
  load : (String) -> Bytes?,
  installed? : Array[(String, String)] = [],
) -> Result[BundlePlan, BundleError] {
  if paths.length() == 0 {
    return Err(EmptyBundle)
  }
  if paths.length() > policy.max_files {
    return Err(TooManyFiles(paths.length(), policy.max_files))
  }
  let seen : Array[String] = []
  let tickets : Array[Ticket] = []
  let current : Array[String] = []
  let mut total = 0L
  for path in paths {
    if seen.contains(path) {
      return Err(DuplicatePath(path))
    }
    seen.push(path)
    let mut installed_hash = ""
    for entry in installed {
      let (installed_path, digest) = entry
      if installed_path == path {
        installed_hash = digest
        break
      }
    }
    let decision = match
      evaluate(
        client,
        path,
        policy.artifact_policy,
        load,
        installed_sha256=installed_hash,
      ) {
      Ok(value) => value
      Err(error) => return Err(Admission(error))
    }
    match decision {
      Current => current.push(path)
      Download(ticket) => {
        if ticket.length() > policy.max_total_bytes - total {
          return Err(
            TotalTooLarge(total + ticket.length(), policy.max_total_bytes),
          )
        }
        total += ticket.length()
        tickets.push(ticket)
      }
    }
  }
  let snapshot_version = match client.snapshot_version() {
    Some(value) => value
    None => return Err(Admission(Client(@client.MissingStage("snapshot"))))
  }
  Ok({
    tickets,
    current_paths: current,
    total_bytes: total,
    root_version: client.root_version(),
    snapshot_version,
  })
}

///|
/// Verify a small in-memory bundle in ticket order. No result is released
/// until every candidate has passed; for large files, use each ticket's
/// open_download_stream and stage all files until the host's atomic commit.
pub fn verify_bundle(
  client : @client.Client,
  plan : BundlePlan,
  candidates : Array[Bytes],
  load : (String) -> Bytes?,
) -> Result[Array[@client.VerifiedTarget], BundleError] {
  if candidates.length() != plan.tickets.length() {
    return Err(WrongCandidateCount(plan.tickets.length(), candidates.length()))
  }
  if client.root_version() != plan.root_version ||
    client.snapshot_version() != Some(plan.snapshot_version) {
    return Err(Admission(StaleTicket))
  }
  let verified : Array[@client.VerifiedTarget] = []
  for index in 0..<plan.tickets.length() {
    let result = match
      verify_download(client, plan.tickets[index], candidates[index], load) {
      Ok(value) => value
      Err(error) => return Err(Admission(error))
    }
    verified.push(result)
  }
  Ok(verified)
}

///|
/// A bounded streaming session verifies the planned files in ticket order.
/// The host owns temporary files; this session never installs them. Any
/// failed write or finalize permanently closes the session, so a partial
/// release can never be mistaken for a verified bundle.
pub struct BundleSession {
  streams : Array[@client.TargetStream]
  mut next_index : Int
  mut closed : Bool
  receipts : Array[@client.VerifiedStream]
}

///|
pub fn BundleSession::next_index(self : BundleSession) -> Int {
  self.next_index
}

///|
pub fn BundleSession::remaining_files(self : BundleSession) -> Int {
  self.streams.length() - self.next_index
}

///|
pub fn BundleSession::closed(self : BundleSession) -> Bool {
  self.closed
}

///|
/// Open all stream verifiers before the first candidate byte is read. This
/// catches stale tickets, unavailable delegated metadata, and file budgets
/// before the host allocates staging resources for the bundle.
pub fn open_bundle_session(
  client : @client.Client,
  plan : BundlePlan,
  load : (String) -> Bytes?,
) -> Result[BundleSession, BundleError] {
  if client.root_version() != plan.root_version ||
    client.snapshot_version() != Some(plan.snapshot_version) {
    return Err(Admission(StaleTicket))
  }
  let streams : Array[@client.TargetStream] = []
  for ticket in plan.tickets {
    let stream = match open_download_stream(client, ticket, load) {
      Ok(value) => value
      Err(error) => return Err(Admission(error))
    }
    streams.push(stream)
  }
  Ok({ streams, next_index: 0, closed: false, receipts: [], })
}

///|
/// Supply a chunk for the current file. An out-of-order chunk is rejected
/// without consuming bytes, while a failed hash/length write closes the
/// entire session.
pub fn BundleSession::write_file(
  self : BundleSession,
  index : Int,
  chunk : Bytes,
) -> Result[Unit, BundleError] {
  if self.closed {
    return Err(SessionClosed)
  }
  if index != self.next_index || index >= self.streams.length() {
    return Err(StreamOrder(self.next_index, index))
  }
  match self.streams[index].write(chunk) {
    Ok(_) => Ok(())
    Err(error) => {
      self.closed = true
      Err(Admission(Client(error)))
    }
  }
}

///|
/// Finalize the current file. A receipt is retained internally until every
/// file in the bundle has been finalized; it is not an installation permit.
pub fn BundleSession::finish_file(
  self : BundleSession,
  index : Int,
) -> Result[Unit, BundleError] {
  if self.closed {
    return Err(SessionClosed)
  }
  if index != self.next_index || index >= self.streams.length() {
    return Err(StreamOrder(self.next_index, index))
  }
  match self.streams[index].finish() {
    Ok(receipt) => {
      self.receipts.push(receipt)
      self.next_index += 1
      Ok(())
    }
    Err(error) => {
      self.closed = true
      Err(Admission(Client(error)))
    }
  }
}

///|
/// Release receipts only when the complete planned bundle has passed. The
/// host must still atomically publish staged files, or roll them all back.
pub fn BundleSession::finish_bundle(
  self : BundleSession,
) -> Result[Array[@client.VerifiedStream], BundleError] {
  if self.closed {
    return Err(SessionClosed)
  }
  if self.next_index != self.streams.length() {
    return Err(BundleIncomplete(self.next_index, self.streams.length()))
  }
  self.closed = true
  Ok(self.receipts.copy())
}
