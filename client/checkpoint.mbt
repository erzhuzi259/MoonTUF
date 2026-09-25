///|
/// Checkpoints are a local persistence format, not a trust bootstrap. The
/// caller must protect the locally trusted root against replacement. The
/// trailing SHA-256 detects accidental corruption, not malicious tampering.
fn append_u32(output : Array[Byte], value : Int) -> Unit {
  output.push(((value >> 24) & 255).to_byte())
  output.push(((value >> 16) & 255).to_byte())
  output.push(((value >> 8) & 255).to_byte())
  output.push((value & 255).to_byte())
}

///|
fn read_u32(input : Bytes, start : Int) -> Int? {
  if start < 0 || start > input.length() - 4 {
    return None
  }
  let a = input[start].to_int()
  if a > 127 {
    return None
  }
  Some(
    (a << 24) |
    (input[start + 1].to_int() << 16) |
    (input[start + 2].to_int() << 8) |
    input[start + 3].to_int(),
  )
}

///|
fn append_bytes(output : Array[Byte], input : Bytes) -> Unit {
  append_u32(output, input.length())
  for byte in input {
    output.push(byte)
  }
}

///|
fn read_bytes(input : Bytes, cursor : Int, body_end : Int) -> (Bytes, Int)? {
  let length = match read_u32(input, cursor) {
    Some(value) => value
    None => return None
  }
  let start = cursor + 4
  if start > body_end || length > body_end - start {
    return None
  }
  let end = start + length
  Some((Bytes::from_array(input[start:end].to_array()), end))
}

///|
/// Export a complete, currently trusted four-role chain. Partial refresh
/// outcomes retain accepted metadata separately and cannot form a checkpoint.
pub fn Client::checkpoint(self : Client) -> Result[Bytes, ClientError] {
  if !self.ready() {
    return Err(MissingStage("complete metadata chain"))
  }
  let timestamp = match self.timestamp {
    Some(value) => value
    None => return Err(MissingStage("timestamp"))
  }
  let snapshot = match self.snapshot {
    Some(value) => value
    None => return Err(MissingStage("snapshot"))
  }
  let targets = match self.targets {
    Some(value) => value
    None => return Err(MissingStage("targets"))
  }
  let output : Array[Byte] = []
  for byte in @utf8.encode("MTUF1") {
    output.push(byte)
  }
  append_bytes(output, self.root.envelope().raw())
  append_bytes(output, timestamp.envelope().raw())
  append_bytes(output, snapshot.envelope().raw())
  append_bytes(output, targets.envelope().raw())
  let digest = @crypto.sha256(Bytes::from_array(output))
  for byte in digest {
    output.push(byte)
  }
  Ok(Bytes::from_array(output))
}

///|
priv struct CheckpointParts {
  root : Bytes
  timestamp : Bytes
  snapshot : Bytes
  targets : Bytes
}

///|
fn decode_checkpoint(
  raw : Bytes,
  budget : Budgets,
) -> Result[CheckpointParts, ClientError] {
  let total_maximum = 5 +
    4 * 4 +
    32 +
    budget.max_root_bytes +
    budget.max_timestamp_bytes +
    budget.max_snapshot_bytes +
    budget.max_targets_bytes
  if raw.length() > total_maximum {
    return Err(ResourceLimit("checkpoint", raw.length(), total_maximum))
  }
  if raw.length() < 5 + 4 * 4 + 32 {
    return Err(CheckpointMalformed("truncated header"))
  }
  let magic = @utf8.encode("MTUF1")
  for index in 0..<magic.length() {
    if raw[index] != magic[index] {
      return Err(CheckpointMalformed("unknown checkpoint format"))
    }
  }
  let body_end = raw.length() - 32
  let calculated = @crypto.sha256(Bytes::from_array(raw[0:body_end].to_array()))
  let expected = Bytes::from_array(raw[body_end:raw.length()].to_array())
  if !@spec.eq(calculated[:], expected[:]) {
    return Err(CheckpointMalformed("checksum mismatch"))
  }
  let (root, cursor1) = match read_bytes(raw, 5, body_end) {
    Some(value) => value
    None => return Err(CheckpointMalformed("invalid root length"))
  }
  let (timestamp, cursor2) = match read_bytes(raw, cursor1, body_end) {
    Some(value) => value
    None => return Err(CheckpointMalformed("invalid timestamp length"))
  }
  let (snapshot, cursor3) = match read_bytes(raw, cursor2, body_end) {
    Some(value) => value
    None => return Err(CheckpointMalformed("invalid snapshot length"))
  }
  let (targets, cursor4) = match read_bytes(raw, cursor3, body_end) {
    Some(value) => value
    None => return Err(CheckpointMalformed("invalid targets length"))
  }
  if cursor4 != body_end {
    return Err(CheckpointMalformed("unexpected bytes in checkpoint body"))
  }
  match guard_size("root", root, budget.max_root_bytes) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  match guard_size("timestamp", timestamp, budget.max_timestamp_bytes) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  match guard_size("snapshot", snapshot, budget.max_snapshot_bytes) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  match guard_size("targets", targets, budget.max_targets_bytes) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  Ok({ root, timestamp, snapshot, targets, })
}

///|
/// Restore and reverify a checkpoint at a new fixed update start time. The
/// caller MUST provide its independently authenticated trusted root; a
/// self-signed root inside the checkpoint is not a trust anchor. Expired saved
/// metadata remains rollback history but cannot authorize target bytes.
pub fn restore_checkpoint(
  encoded : Bytes,
  trusted_root_raw : Bytes,
  update_start : String,
  budget? : Budgets = budgets(),
) -> Result[Client, ClientError] {
  let parts = match decode_checkpoint(encoded, budget) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  if !@spec.eq(parts.root[:], trusted_root_raw[:]) {
    return Err(CheckpointRootMismatch)
  }
  let anchor = match
    open_trusted_root(trusted_root_raw, update_start, budget~) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let timestamp = match
    @model.parse_timestamp(
      parts.timestamp,
      limits=wire_limits(budget.max_timestamp_bytes, budget),
    ) {
    Ok(value) => value
    Err(error) => return Err(Model(error))
  }
  match
    @trust.verify_top_level(anchor.root, "timestamp", timestamp.envelope()) {
    Ok(_) => ()
    Err(error) => return Err(Trust(error))
  }
  match
    check_metafile(
      "snapshot",
      parts.snapshot,
      timestamp.snapshot(),
      budget.max_snapshot_bytes,
    ) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  let snapshot = match
    @model.parse_snapshot(
      parts.snapshot,
      limits=wire_limits(budget.max_snapshot_bytes, budget),
    ) {
    Ok(value) => value
    Err(error) => return Err(Model(error))
  }
  match @trust.verify_top_level(anchor.root, "snapshot", snapshot.envelope()) {
    Ok(_) => ()
    Err(error) => return Err(Trust(error))
  }
  let expected_snapshot = timestamp.snapshot().version()
  if snapshot.common().version() != expected_snapshot {
    return Err(
      VersionMismatch(
        "snapshot",
        expected_snapshot,
        snapshot.common().version(),
      ),
    )
  }
  let target_pin = match snapshot.metafile("targets.json") {
    Some(value) => value
    None => return Err(MissingDescriptor("targets.json"))
  }
  match
    check_metafile(
      "targets",
      parts.targets,
      target_pin,
      budget.max_targets_bytes,
    ) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  let targets = match
    @model.parse_targets(
      parts.targets,
      limits=wire_limits(budget.max_targets_bytes, budget),
    ) {
    Ok(value) => value
    Err(error) => return Err(Model(error))
  }
  match @trust.verify_top_level(anchor.root, "targets", targets.envelope()) {
    Ok(_) => ()
    Err(error) => return Err(Trust(error))
  }
  if targets.common().version() != target_pin.version() {
    return Err(
      VersionMismatch(
        "targets",
        target_pin.version(),
        targets.common().version(),
      ),
    )
  }
  Ok({
    root: anchor.root,
    timestamp: Some(timestamp),
    snapshot: Some(snapshot),
    previous_snapshot: Some(snapshot),
    targets: Some(targets),
    update_start,
    budget,
    root_rotations: 0,
  })
}
