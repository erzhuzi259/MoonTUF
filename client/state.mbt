///|
/// A protected-local-store format, NOT a downloaded trust bootstrap. Unlike a
/// complete checkpoint, it retains rollback baselines after a partial refresh.
pub fn Client::save_state(self : Client) -> Bytes {
  let fields : Array[(String, @wire.Value)] = [
    ("format", @wire.Text("MTUF2")),
    ("root", @wire.Text(@crypto.encode_hex(self.root.envelope().raw()))),
    ("time", @wire.Text(self.update_start)),
  ]
  for
    (name, envelope) in [
      ("timestamp", self.timestamp.map(fn(v) { v.envelope() })),
      ("timestampBaseline", self.timestamp_baseline.map(fn(v) { v.envelope() })),
      ("snapshot", self.snapshot.map(fn(v) { v.envelope() })),
      ("previousSnapshot", self.previous_snapshot.map(fn(v) { v.envelope() })),
      ("targets", self.targets.map(fn(v) { v.envelope() })),
    ] {
    fields.push(
      (
        name,
        match envelope {
          Some(value) => @wire.Text(@crypto.encode_hex(value.raw()))
          None => @wire.Null
        },
      ),
    )
  }
  @wire.canonical(@wire.Dict(fields))
}

///|
fn state_bytes(
  value : @wire.Value,
  name : String,
) -> Result[Bytes?, ClientError] {
  match value.field(name) {
    Some(@wire.Null) => Ok(None)
    Some(@wire.Text(hex)) =>
      match @crypto.decode_hex(hex) {
        Ok(bytes) => Ok(Some(bytes))
        Err(_) => Err(CheckpointMalformed(name))
      }
    _ => Err(CheckpointMalformed(name))
  }
}

///|
/// The caller must protect this store and supply its independently retained
/// latest trusted root. Old expired metadata is rollback history only. It is
/// reverified cryptographically but cannot authorize downloads until refreshed.
pub fn restore_state(
  raw : Bytes,
  trusted_root_raw : Bytes,
  update_start : String,
  budget~ : Budgets = budgets(),
) -> Result[Client, ClientError] {
  let value = match
    @wire.parse(
      raw,
      limits=@wire.limits(
        max_bytes=2 *
          (
            budget.max_root_bytes +
            2 * budget.max_timestamp_bytes +
            2 * budget.max_snapshot_bytes +
            budget.max_targets_bytes
          ) +
          4096,
        max_depth=8,
      ),
    ) {
    Ok(value) => value
    Err(_) => return Err(CheckpointMalformed("local state JSON"))
  }
  if !(value.field("format") is Some(@wire.Text("MTUF2"))) {
    return Err(CheckpointMalformed("local state format"))
  }
  let root = match state_bytes(value, "root") {
    Ok(Some(value)) => value
    _ => return Err(CheckpointRootMismatch)
  }
  if !@spec.eq(root[:], trusted_root_raw[:]) {
    return Err(CheckpointRootMismatch)
  }
  let anchor = match open_trusted_root(root, update_start, budget~) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let previous_time = match value.field("time") {
    Some(@wire.Text(value)) => value
    _ => return Err(CheckpointMalformed("time"))
  }
  if !@model.valid_utc_time(previous_time) || previous_time > update_start {
    return Err(ClockRollback(previous_time, update_start))
  }
  let timestamps : Array[@model.Timestamp?] = []
  for name in ["timestamp", "timestampBaseline"] {
    let bytes = match state_bytes(value, name) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let parsed = match bytes {
      Some(bytes) => {
        let parsed = match
          @model.parse_timestamp(
            bytes,
            limits=wire_limits(budget.max_timestamp_bytes, budget),
          ) {
          Ok(value) => value
          Err(error) => return Err(Model(error))
        }
        match
          @trust.verify_top_level(anchor.root, "timestamp", parsed.envelope()) {
          Ok(_) => ()
          Err(error) => return Err(Trust(error))
        }
        Some(parsed)
      }
      None => None
    }
    timestamps.push(parsed)
  }
  let snapshots : Array[@model.Snapshot?] = []
  for name in ["snapshot", "previousSnapshot"] {
    let bytes = match state_bytes(value, name) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let parsed = match bytes {
      Some(bytes) => {
        let parsed = match
          @model.parse_snapshot(
            bytes,
            limits=wire_limits(budget.max_snapshot_bytes, budget),
          ) {
          Ok(value) => value
          Err(error) => return Err(Model(error))
        }
        match
          @trust.verify_top_level(anchor.root, "snapshot", parsed.envelope()) {
          Ok(_) => ()
          Err(error) => return Err(Trust(error))
        }
        Some(parsed)
      }
      None => None
    }
    snapshots.push(parsed)
  }
  let targets = match state_bytes(value, "targets") {
    Ok(Some(bytes)) => {
      let parsed = match
        @model.parse_targets(
          bytes,
          limits=wire_limits(budget.max_targets_bytes, budget),
        ) {
        Ok(value) => value
        Err(error) => return Err(Model(error))
      }
      match @trust.verify_top_level(anchor.root, "targets", parsed.envelope()) {
        Ok(_) => ()
        Err(error) => return Err(Trust(error))
      }
      Some(parsed)
    }
    Ok(None) => None
    Err(error) => return Err(error)
  }
  if snapshots[0] is Some(snapshot) {
    let timestamp = match timestamps[0] {
      Some(value) => value
      None => return Err(MissingStage("timestamp"))
    }
    if snapshot.common().version() != timestamp.snapshot().version() {
      return Err(CheckpointMalformed("snapshot version pin"))
    }
    match
      check_metafile(
        "snapshot",
        snapshot.envelope().raw(),
        timestamp.snapshot(),
        budget.max_snapshot_bytes,
      ) {
      Ok(_) => ()
      Err(error) => return Err(error)
    }
  }
  if targets is Some(targets) {
    let snapshot = match snapshots[0] {
      Some(value) => value
      None => return Err(MissingStage("snapshot"))
    }
    let pin = match snapshot.metafile("targets.json") {
      Some(value) => value
      None => return Err(MissingDescriptor("targets.json"))
    }
    if targets.common().version() != pin.version() {
      return Err(CheckpointMalformed("targets version pin"))
    }
    match
      check_metafile(
        "targets",
        targets.envelope().raw(),
        pin,
        budget.max_targets_bytes,
      ) {
      Ok(_) => ()
      Err(error) => return Err(error)
    }
  }
  Ok({
    root: anchor.root,
    timestamp: timestamps[0],
    timestamp_baseline: timestamps[1],
    snapshot: snapshots[0],
    previous_snapshot: snapshots[1],
    targets,
    update_start,
    budget,
    root_rotations: 0,
    root_chain_complete: false,
  })
}
