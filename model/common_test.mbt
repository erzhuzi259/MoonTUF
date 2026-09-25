///|
test "metadata envelope preserves raw and canonical signed bytes separately" {
  let raw = @utf8.encode(
    "{\"signatures\":[{\"keyid\":\"first\",\"sig\":\"aa\"}],\"signed\":{\"version\":1,\"_type\":\"root\"}}",
  )
  let envelope = parse_envelope(raw).unwrap()
  assert_eq(envelope.raw().length(), raw.length())
  let signed = @utf8.decode(envelope.canonical_signed()) catch {
    _ => abort("canonical bytes are not UTF-8")
  }
  assert_eq(signed, "{\"_type\":\"root\",\"version\":1}")
  assert_eq(envelope.signatures().length(), 1)
}

///|
test "same signer cannot appear twice in an envelope" {
  let raw = @utf8.encode(
    "{\"signed\":{},\"signatures\":[{\"keyid\":\"x\",\"sig\":\"aa\"},{\"keyid\":\"x\",\"sig\":\"bb\"}]}",
  )
  assert_true(parse_envelope(raw) is Err(DuplicateItem(_)))
}

///|
test "UTC expiry parser validates Gregorian dates" {
  assert_true(valid_utc_time("2028-02-29T23:59:59Z"))
  assert_false(valid_utc_time("2027-02-29T23:59:59Z"))
  assert_false(valid_utc_time("2026-13-01T00:00:00Z"))
  assert_false(valid_utc_time("2026-09-25T24:00:00Z"))
  assert_false(valid_utc_time("2026-09-25T12:00:60Z"))
  assert_true(expired("2026-09-25T00:00:00Z", "2026-09-25T00:00:00Z"))
  assert_false(expired("2026-09-25T00:00:01Z", "2026-09-25T00:00:00Z"))
}

///|
test "common metadata refuses unknown spec and invalid expiry" {
  let malformed = @wire.parse(
    @utf8.encode(
      "{\"_type\":\"root\",\"spec_version\":\"2.0.0\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\"}",
    ),
  ).unwrap()
  assert_true(parse_common(malformed, "root") is Err(UnsupportedSpec(_)))
  let expired_format = @wire.parse(
    @utf8.encode(
      "{\"_type\":\"root\",\"spec_version\":\"1.0.0\",\"version\":1,\"expires\":\"2030-02-30T00:00:00Z\"}",
    ),
  ).unwrap()
  assert_true(parse_common(expired_format, "root") is Err(InvalidValue(_, _)))
}
