///|
pub(all) enum RefreshStatus {
  Complete
  Unchanged
  Failed(ClientError)
} derive(Debug)

///|
/// Metadata accepted during a refresh. The host may persist these documents
/// in order after inspecting the outcome; it should also retain its prior
/// trusted state until all replacements are durable.
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
/// not perform I/O. Missing N+1 root means the root chain is complete, while
/// missing any later top-level role is a failure. The outcome retains all
/// successfully accepted state even when a later stage fails.
pub fn Client::refresh(
  self : Client,
  load : (String) -> Bytes?,
) -> RefreshOutcome {
  let mut current = self
  let accepted : Array[AcceptedMetadata] = []
  while current.next_root_name() is Some(name) {
    let candidate = match load(name) {
      Some(bytes) => bytes
      None => break
    }
    current = match current.advance_root(candidate) {
      Ok(value) => value
      Err(error) => return outcome(current, Failed(error), accepted)
    }
    accepted.push({ name: "root.json", raw: candidate, })
  }
  current = match current.finish_root_chain() {
    Ok(value) => value
    Err(error) => return outcome(current, Failed(error), accepted)
  }
  let timestamp_raw = match load("timestamp.json") {
    Some(bytes) => bytes
    None =>
      return outcome(
        current,
        Failed(MetadataUnavailable("timestamp.json")),
        accepted,
      )
  }
  let after_timestamp = match current.accept_timestamp(timestamp_raw) {
    Ok(value) => value
    Err(Unchanged(_, _)) =>
      match current.check_complete_fresh() {
        Ok(_) => return outcome(current, Unchanged, accepted)
        Err(error) => return outcome(current, Failed(error), accepted)
      }
    Err(error) => return outcome(current, Failed(error), accepted)
  }
  current = after_timestamp
  accepted.push({ name: "timestamp.json", raw: timestamp_raw, })
  let snapshot_name = match current.snapshot_request_name() {
    Ok(value) => value
    Err(error) => return outcome(current, Failed(error), accepted)
  }
  let snapshot_raw = match load(snapshot_name) {
    Some(bytes) => bytes
    None =>
      return outcome(
        current,
        Failed(MetadataUnavailable(snapshot_name)),
        accepted,
      )
  }
  current = match current.accept_snapshot(snapshot_raw) {
    Ok(value) => value
    Err(error) => return outcome(current, Failed(error), accepted)
  }
  accepted.push({ name: "snapshot.json", raw: snapshot_raw, })
  let targets_name = match current.targets_request_name() {
    Ok(value) => value
    Err(error) => return outcome(current, Failed(error), accepted)
  }
  let targets_raw = match load(targets_name) {
    Some(bytes) => bytes
    None =>
      return outcome(
        current,
        Failed(MetadataUnavailable(targets_name)),
        accepted,
      )
  }
  current = match current.accept_targets(targets_raw) {
    Ok(value) => value
    Err(error) => return outcome(current, Failed(error), accepted)
  }
  accepted.push({ name: "targets.json", raw: targets_raw, })
  outcome(current, Complete, accepted)
}
