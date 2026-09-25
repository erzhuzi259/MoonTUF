///|
test "diagnostic codes remain stable and omit attacker-controlled path" {
  let failure = @client.HashMismatch("models/private/secret.bin")
  let report = diagnose(failure)
  assert_eq(report.code(), "integrity.sha256")
  assert_eq(report.stage(), "metadata")
  let json = report.to_json()
  assert_true(json.contains("\"schema\":\"moontuf.diagnostic.v1\""))
  assert_false(json.contains("private"))
  assert_true(json.contains("\"code\":\"integrity.sha256\""))
}

///|
test "absence of metadata is retryable while bad signatures are not" {
  let unavailable = diagnose(@client.MetadataUnavailable("timestamp.json"))
  assert_true(unavailable.retryable())
  let bad = diagnose(@client.Trust(@trust.ThresholdNotMet("root", 0, 1)))
  assert_false(bad.retryable())
  assert_eq(bad.code(), "trust.threshold")
}

///|
test "parse errors map to bounded JSON categories" {
  let error = @client.Model(@model.Wire(@wire.DuplicateKey("a")))
  assert_eq(diagnose(error).code(), "json.duplicate_key")
}
