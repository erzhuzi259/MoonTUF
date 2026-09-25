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
  Ok({ artifact_policy, max_files, max_total_bytes })
}

///|
pub(all) enum BundleError {
  Admission(AdmissionError)
  EmptyBundle
  DuplicatePath(String)
  TooManyFiles(Int, Int)
  TotalTooLarge(Int64, Int64)
  WrongCandidateCount(Int, Int)
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
pub fn BundlePlan::total_bytes(self : BundlePlan) -> Int64 { self.total_bytes }

///|
pub fn BundlePlan::root_version(self : BundlePlan) -> Int { self.root_version }

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
  if paths.length() == 0 { return Err(EmptyBundle) }
  if paths.length() > policy.max_files {
    return Err(TooManyFiles(paths.length(), policy.max_files))
  }
  let seen : Array[String] = []
  let tickets : Array[Ticket] = []
  let current : Array[String] = []
  let mut total = 0L
  for path in paths {
    if seen.contains(path) { return Err(DuplicatePath(path)) }
    seen.push(path)
    let mut installed_hash = ""
    for entry in installed {
      let (installed_path, digest) = entry
      if installed_path == path {
        installed_hash = digest
        break
      }
    }
    let decision = match evaluate(
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
          return Err(TotalTooLarge(total + ticket.length(), policy.max_total_bytes))
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
    let result = match verify_download(
      client,
      plan.tickets[index],
      candidates[index],
      load,
    ) {
      Ok(value) => value
      Err(error) => return Err(Admission(error))
    }
    verified.push(result)
  }
  Ok(verified)
}
