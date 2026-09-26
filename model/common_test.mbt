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
test "envelope signed AST mutations cannot change nested authenticated data" {
  let raw = @utf8.encode(
    "{\"signed\":{\"version\":1,\"nested\":{\"channels\":[{\"name\":\"stable\"}]}},\"signatures\":[]}",
  )
  let envelope = parse_envelope(raw).unwrap()
  let original = envelope.canonical_signed()
  let exposed = envelope.signed()
  let channels = exposed
    .field("nested")
    .unwrap()
    .field("channels")
    .unwrap()
    .as_list()
    .unwrap()
  let channel = channels[0].as_dict().unwrap()
  channel[0] = ("name", Text("untrusted"))
  channels.push(Text("injected"))
  assert_eq(channels.length(), 2)
  assert_eq(channels[0].field("name").unwrap().as_text(), Some("untrusted"))
  assert_eq(@wire.canonical(envelope.signed()).to_array(), original.to_array())
  assert_eq(envelope.canonical_signed().to_array(), original.to_array())
  assert_eq(envelope.raw().to_array(), raw.to_array())
}

///|
test "same signer cannot appear twice in an envelope" {
  let raw = @utf8.encode(
    "{\"signed\":{},\"signatures\":[{\"keyid\":\"x\",\"sig\":\"aa\"},{\"keyid\":\"x\",\"sig\":\"bb\"}]}",
  )
  assert_true(parse_envelope(raw) is Err(DuplicateItem(_)))
}

///|
test "large signature list preserves order and rejects a late duplicate" {
  let mut entries = ""
  for index in 0..<512 {
    if index > 0 {
      entries += ","
    }
    entries += "{\"keyid\":\"key-" + index.to_string() + "\",\"sig\":\"aa\"}"
  }
  let prefix = "{\"signed\":{},\"signatures\":["
  let envelope = parse_envelope(@utf8.encode(prefix + entries + "]}")).unwrap()
  let signatures = envelope.signatures()
  assert_eq(signatures.length(), 512)
  assert_eq(signatures[0].keyid(), "key-0")
  assert_eq(signatures[511].keyid(), "key-511")
  let repeated = prefix + entries + ",{\"keyid\":\"key-256\",\"sig\":\"bb\"}]}"
  assert_true(parse_envelope(@utf8.encode(repeated)) is Err(DuplicateItem(_)))
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
