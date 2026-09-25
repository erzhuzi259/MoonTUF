///|
test "timestamp binds snapshot version and optional integrity" {
  let raw = @utf8.encode(
    "{\"signed\":{\"_type\":\"timestamp\",\"spec_version\":\"1.0.0\",\"version\":3,\"expires\":\"2030-01-01T00:00:00Z\",\"meta\":{\"snapshot.json\":{\"version\":5,\"length\":10,\"hashes\":{\"sha256\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"}}}},\"signatures\":[]}",
  )
  let timestamp = parse_timestamp(raw).unwrap()
  assert_eq(timestamp.common().version(), 3)
  assert_eq(timestamp.snapshot().version(), 5)
  assert_eq(timestamp.snapshot().length(), Some(10))
}

///|
test "snapshot requires targets metadata and safe names" {
  let valid = @utf8.encode(
    "{\"signed\":{\"_type\":\"snapshot\",\"spec_version\":\"1.0.0\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"meta\":{\"targets.json\":{\"version\":1},\"delegated/a.json\":{\"version\":2}}},\"signatures\":[]}",
  )
  let snapshot = parse_snapshot(valid).unwrap()
  assert_eq(snapshot.metafile("delegated/a.json").unwrap().version(), 2)
  assert_true(safe_metadata_name("delegated/a.json"))
  assert_false(safe_metadata_name("../evil.json"))
  assert_false(safe_metadata_name("C:\\evil.json"))
}

///|
test "snapshot rejects missing top-level targets" {
  let invalid = @utf8.encode(
    "{\"signed\":{\"_type\":\"snapshot\",\"spec_version\":\"1.0.0\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"meta\":{}},\"signatures\":[]}",
  )
  assert_true(parse_snapshot(invalid) is Err(MissingField(_)))
}

///|
test "declared SHA-256 must be a 32-byte digest" {
  let invalid = @utf8.encode(
    "{\"signed\":{\"_type\":\"timestamp\",\"spec_version\":\"1.0.0\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"meta\":{\"snapshot.json\":{\"version\":1,\"hashes\":{\"sha256\":\"00\"}}}},\"signatures\":[]}",
  )
  assert_true(parse_timestamp(invalid) is Err(InvalidValue(_, _)))
}
