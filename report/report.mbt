///|
/// Stable, non-secret failure classification for host logs and UX. Raw remote
/// metadata and signature bytes are deliberately excluded from messages.
pub struct Diagnostic {
  code : String
  stage : String
  summary : String
  retryable : Bool
}

///|
pub fn Diagnostic::code(self : Diagnostic) -> String { self.code }

///|
pub fn Diagnostic::stage(self : Diagnostic) -> String { self.stage }

///|
pub fn Diagnostic::summary(self : Diagnostic) -> String { self.summary }

///|
pub fn Diagnostic::retryable(self : Diagnostic) -> Bool { self.retryable }

///|
fn diagnostic(code : String, stage : String, summary : String, retryable : Bool) -> Diagnostic {
  { code, stage: safe_stage(stage), summary, retryable }
}

///|
/// Error payloads may contain remote target or delegated-role names. Collapse
/// them to a fixed vocabulary before emitting an operational JSON record.
fn safe_stage(raw : String) -> String {
  match raw {
    "root" | "timestamp" | "snapshot" | "targets" |
    "target" | "delegation" | "restore" | "clock" | "signature" => raw
    _ =>
      if raw.has_prefix("target:") {
        "target"
      } else if raw.has_prefix("delegated:") {
        "delegation"
      } else {
        "metadata"
      }
  }
}

///|
fn model_diagnostic(error : @model.ModelError) -> Diagnostic {
  match error {
    @model.Wire(problem) => wire_diagnostic(problem)
    @model.MissingField(_) =>
      diagnostic("metadata.missing_field", "parse", "Required TUF field is absent.", false)
    @model.WrongType(_) =>
      diagnostic("metadata.wrong_type", "parse", "TUF field has an unexpected JSON type.", false)
    @model.InvalidValue(_, _) =>
      diagnostic("metadata.invalid_value", "parse", "TUF field is outside its permitted range.", false)
    @model.DuplicateItem(_) =>
      diagnostic("metadata.duplicate_item", "parse", "A TUF list contains a repeated identity.", false)
    @model.UnsupportedSpec(_) =>
      diagnostic("metadata.unsupported_spec", "parse", "Metadata specification version is not supported.", false)
    @model.InvalidKeyId(_) =>
      diagnostic("metadata.key_id", "parse", "Public key identifier does not match its canonical key.", false)
  }
}

///|
fn wire_diagnostic(error : @wire.WireError) -> Diagnostic {
  match error {
    @wire.InputTooLarge(_, _) =>
      diagnostic("json.input_limit", "parse", "JSON metadata exceeds its byte budget.", false)
    @wire.NestingTooDeep(_) =>
      diagnostic("json.depth_limit", "parse", "JSON metadata exceeds its nesting budget.", false)
    @wire.TooManyNodes(_) =>
      diagnostic("json.node_limit", "parse", "JSON metadata exceeds its node budget.", false)
    @wire.TooManyMembers(_) =>
      diagnostic("json.member_limit", "parse", "JSON object or array exceeds its member budget.", false)
    @wire.NumberTooLong(_) =>
      diagnostic("json.integer_limit", "parse", "JSON integer exceeds its digit budget.", false)
    @wire.InvalidJson(_, _) =>
      diagnostic("json.invalid", "parse", "Metadata is not valid TUF-profile JSON.", false)
    @wire.DuplicateKey(_) =>
      diagnostic("json.duplicate_key", "parse", "JSON object has an ambiguous repeated key.", false)
    @wire.NonIntegerNumber(_) =>
      diagnostic("json.noninteger", "parse", "TUF-profile JSON does not allow floating-point numbers.", false)
  }
}

///|
fn trust_diagnostic(error : @trust.TrustError) -> Diagnostic {
  match error {
    @trust.UnknownRole(_) =>
      diagnostic("trust.unknown_role", "signature", "No authority is configured for this role.", false)
    @trust.InvalidThreshold(_, _) =>
      diagnostic("trust.invalid_threshold", "signature", "Signature threshold cannot be satisfied.", false)
    @trust.ThresholdNotMet(_, _, _) =>
      diagnostic("trust.threshold", "signature", "Distinct valid signatures do not meet the role threshold.", false)
    @trust.MalformedSignature(_) =>
      diagnostic("trust.malformed_signature", "signature", "A declared signature has an invalid encoding.", false)
    @trust.UnsupportedKey(_) =>
      diagnostic("trust.unsupported_key", "signature", "An authorized key is unavailable.", false)
  }
}

///|
/// Translate all client errors into stable machine codes. Codes are versioned
/// as part of MoonTUF's public surface; callers should branch on code, not on
/// an English summary string.
pub fn diagnose(error : @client.ClientError) -> Diagnostic {
  match error {
    @client.Model(problem) => model_diagnostic(problem)
    @client.Trust(problem) => trust_diagnostic(problem)
    @client.InvalidStartTime(_) =>
      diagnostic("clock.invalid_start", "clock", "Update start time must be strict UTC.", false)
    @client.Expired(role) =>
      diagnostic("metadata.expired", role, "Metadata expired before the update began.", false)
    @client.MissingStage(stage) =>
      diagnostic("state.missing_stage", stage, "A required trust stage has not completed.", true)
    @client.VersionMismatch(stage, _, _) =>
      diagnostic("metadata.version", stage, "Metadata version does not match its trusted parent.", false)
    @client.Rollback(stage, _, _) =>
      diagnostic("metadata.rollback", stage, "Proposed metadata would roll back trusted state.", false)
    @client.Unchanged(stage, _) =>
      diagnostic("metadata.unchanged", stage, "No newer metadata is available.", false)
    @client.ResourceLimit(stage, _, _) =>
      diagnostic("resource.metadata_limit", stage, "Metadata exceeds the configured resource budget.", false)
    @client.TargetResourceLimit(stage, _, _) =>
      diagnostic("resource.target_limit", stage, "Target exceeds the configured resource budget.", false)
    @client.LengthMismatch(stage, _, _) =>
      diagnostic("integrity.length", stage, "Candidate byte length differs from trusted metadata.", false)
    @client.HashMismatch(stage) =>
      diagnostic("integrity.sha256", stage, "Candidate SHA-256 differs from trusted metadata.", false)
    @client.MissingDescriptor(stage) =>
      diagnostic("metadata.missing_descriptor", stage, "Trusted parent does not describe this metadata.", false)
    @client.RootRotationLimit(_) =>
      diagnostic("resource.root_rotations", "root", "Root update count exceeds its budget.", false)
    @client.TargetNotFound(_) =>
      diagnostic("target.not_found", "target", "No trusted role describes this target.", false)
    @client.MetadataUnavailable(stage) =>
      diagnostic("metadata.unavailable", stage, "Required metadata was not supplied.", true)
    @client.DelegationLimit(_) =>
      diagnostic("resource.delegations", "delegation", "Delegated role visit count exceeds its budget.", false)
    @client.AlreadyFinished =>
      diagnostic("stream.finished", "target", "Target stream was already finalized.", false)
    @client.CheckpointMalformed(_) =>
      diagnostic("checkpoint.malformed", "restore", "Local checkpoint is corrupt or unsupported.", false)
    @client.CheckpointRootMismatch =>
      diagnostic("checkpoint.root_mismatch", "restore", "Checkpoint root differs from the trusted anchor.", false)
    @client.InvalidPath(_) =>
      diagnostic("target.invalid_path", "target", "Target path is unsafe or malformed.", false)
  }
}

///|
/// A compact JSONL-safe diagnostic record for update agents. No candidate
/// bytes, signatures, keys, or untrusted field values are echoed.
pub fn Diagnostic::to_json(self : Diagnostic) -> String {
  let retryable = if self.retryable { "true" } else { "false" }
  "{" +
    "\"schema\":\"moontuf.diagnostic.v1\"," +
    "\"code\":" + Json::string(self.code).stringify() + "," +
    "\"stage\":" + Json::string(self.stage).stringify() + "," +
    "\"summary\":" + Json::string(self.summary).stringify() + "," +
    "\"retryable\":" + retryable +
    "}"
}
