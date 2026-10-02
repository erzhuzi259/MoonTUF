///|
pub(all) enum RefreshStatus {
  Complete
  Unchanged
  Failed(ClientError)
} derive(Debug)

///|
/// The host must distinguish an authoritative absence (normally HTTP 404)
/// from a transport, timeout, or local I/O failure. Only an absent N+1 root
/// ends root probing; a failure must never silently complete the root chain.
pub(all) enum MetadataResponse {
  MetadataPresent(Bytes)
  MetadataAbsent
  MetadataFailure
} derive(Debug)

///|
/// Metadata accepted during a refresh. Its name is the repository path that
/// was requested, including a version prefix when consistent snapshots are
/// enabled. The host may persist these documents in order after inspecting
/// the outcome; it should retain its prior state until replacements are durable.
pub struct AcceptedMetadata {
  name : String
  raw : Bytes
}

///|
pub fn AcceptedMetadata::name(self : AcceptedMetadata) -> String {
  self.name
}

///|
pub fn AcceptedMetadata::raw(self : AcceptedMetadata) -> Bytes {
  self.raw
}

///|
pub struct RefreshOutcome {
  client : Client
  status : RefreshStatus
  accepted : Array[AcceptedMetadata]
}

///|
pub fn RefreshOutcome::client(self : RefreshOutcome) -> Client {
  self.client
}

///|
pub fn RefreshOutcome::status(self : RefreshOutcome) -> RefreshStatus {
  self.status
}

///|
pub fn RefreshOutcome::accepted(
  self : RefreshOutcome,
) -> Array[AcceptedMetadata] {
  self.accepted.copy()
}

///|
fn outcome(
  client : Client,
  status : RefreshStatus,
  accepted : Array[AcceptedMetadata],
) -> RefreshOutcome {
  { client, status, accepted, }
}

///|
/// Drive a complete refresh over an injected metadata loader. The loader may
/// be backed by memory, disk, a network client, or a test harness; MoonTUF does
/// not perform I/O. Only an authoritative absent N+1 root means the root chain
/// is complete; a fetch failure is never interpreted as absence. Missing any
/// later top-level role is a failure. The outcome retains all
/// successfully accepted state even when a later stage fails. A retry with
/// an equal timestamp resumes missing descendants using the retained pins;
/// it never replaces trusted data with the equal-version candidate.
pub fn Client::refresh(
  self : Client,
  load : (String) -> MetadataResponse,
) -> RefreshOutcome {
  let mut current = self
  let accepted : Array[AcceptedMetadata] = []
  while current.next_root_name() is Some(name) {
    let candidate = match load(name) {
      MetadataPresent(bytes) => bytes
      MetadataAbsent => break
      MetadataFailure =>
        return outcome(current, Failed(MetadataFetchFailure(name)), accepted)
    }
    current = match current.advance_root(candidate) {
      Ok(value) => value
      Err(error) => return outcome(current, Failed(error), accepted)
    }
    accepted.push({ name, raw: candidate, })
  }
  current = match current.finish_root_chain() {
    Ok(value) => value
    Err(error) => return outcome(current, Failed(error), accepted)
  }
  let timestamp_raw = match load("timestamp.json") {
    MetadataPresent(bytes) => bytes
    MetadataAbsent =>
      return outcome(
        current,
        Failed(MetadataUnavailable("timestamp.json")),
        accepted,
      )
    MetadataFailure =>
      return outcome(
        current,
        Failed(MetadataFetchFailure("timestamp.json")),
        accepted,
      )
  }
  match current.accept_timestamp(timestamp_raw) {
    Ok(value) => {
      current = value
      accepted.push({ name: "timestamp.json", raw: timestamp_raw, })
    }
    Err(Unchanged(_, _)) =>
      match current.check_complete_fresh() {
        Ok(_) => return outcome(current, Unchanged, accepted)
        Err(MissingStage("snapshot" | "targets")) => ()
        Err(error) => return outcome(current, Failed(error), accepted)
      }
    Err(error) => return outcome(current, Failed(error), accepted)
  }
  if current.snapshot is None {
    let snapshot_name = match current.snapshot_request_name() {
      Ok(value) => value
      Err(error) => return outcome(current, Failed(error), accepted)
    }
    let snapshot_raw = match load(snapshot_name) {
      MetadataPresent(bytes) => bytes
      MetadataAbsent =>
        return outcome(
          current,
          Failed(MetadataUnavailable(snapshot_name)),
          accepted,
        )
      MetadataFailure =>
        return outcome(
          current,
          Failed(MetadataFetchFailure(snapshot_name)),
          accepted,
        )
    }
    current = match current.accept_snapshot(snapshot_raw) {
      Ok(value) => value
      Err(error) => return outcome(current, Failed(error), accepted)
    }
    accepted.push({ name: snapshot_name, raw: snapshot_raw, })
  }
  let targets_name = match current.targets_request_name() {
    Ok(value) => value
    Err(error) => return outcome(current, Failed(error), accepted)
  }
  let targets_raw = match load(targets_name) {
    MetadataPresent(bytes) => bytes
    MetadataAbsent =>
      return outcome(
        current,
        Failed(MetadataUnavailable(targets_name)),
        accepted,
      )
    MetadataFailure =>
      return outcome(
        current,
        Failed(MetadataFetchFailure(targets_name)),
        accepted,
      )
  }
  current = match current.accept_targets(targets_raw) {
    Ok(value) => value
    Err(error) => return outcome(current, Failed(error), accepted)
  }
  accepted.push({ name: targets_name, raw: targets_raw, })
  match current.check_complete_fresh() {
    Ok(_) => outcome(current, Complete, accepted)
    Err(error) => outcome(current, Failed(error), accepted)
  }
}
