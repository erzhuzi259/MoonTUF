///|
test "targets bind path, length, SHA-256 and opaque custom object" {
  let raw = @utf8.encode(
    "{\"signed\":{\"_type\":\"targets\",\"spec_version\":\"1.0.0\",\"version\":2,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{\"apps/demo.bin\":{\"length\":3,\"hashes\":{\"sha256\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"},\"custom\":{\"channel\":\"stable\"}}}},\"signatures\":[]}",
  )
  let targets = parse_targets(raw).unwrap()
  let file = targets.target("apps/demo.bin").unwrap()
  assert_eq(file.length(), 3)
  assert_true(file.custom() is Some(_))
  assert_eq(targets.common().version(), 2)
}

///|
test "targets reject path traversal and missing SHA-256" {
  let traversal = @utf8.encode(
    "{\"signed\":{\"_type\":\"targets\",\"spec_version\":\"1.0.0\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{\"../evil\":{\"length\":1,\"hashes\":{\"sha256\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"}}}},\"signatures\":[]}",
  )
  assert_true(parse_targets(traversal) is Err(InvalidValue(_, _)))
  assert_false(safe_target_path("/absolute"))
  assert_false(safe_target_path("a//b"))
  assert_false(safe_target_path("a/../b"))
  assert_true(safe_target_path("models/weights-v1.bin"))
  let missing = @utf8.encode(
    "{\"signed\":{\"_type\":\"targets\",\"spec_version\":\"1.0.0\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{\"x\":{\"length\":1,\"hashes\":{\"sha512\":\"abc\"}}}},\"signatures\":[]}",
  )
  assert_true(parse_targets(missing) is Err(InvalidValue(_, _)))
}

///|
test "empty target set is valid metadata" {
  let raw = @utf8.encode(
    "{\"signed\":{\"_type\":\"targets\",\"spec_version\":\"1.0.0\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{}},\"signatures\":[]}",
  )
  assert_eq(parse_targets(raw).unwrap().targets().length(), 0)
}

///|
test "delegations reject unsupported succinct roles" {
  let raw = @utf8.encode(
    "{\"signed\":{\"_type\":\"targets\",\"spec_version\":\"1.0.0\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{},\"delegations\":{\"keys\":{},\"roles\":[],\"succinct_roles\":{}}},\"signatures\":[]}",
  )
  assert_true(parse_targets(raw) is Err(InvalidValue(_, _)))
}

///|
test "target length supports multi-gigabyte streams without truncation" {
  let raw = @utf8.encode(
    "{\"signed\":{\"_type\":\"targets\",\"spec_version\":\"1.0.0\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{\"models/large.bin\":{\"length\":3000000000,\"hashes\":{\"sha256\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"}}}},\"signatures\":[]}",
  )
  assert_eq(
    parse_targets(raw).unwrap().target("models/large.bin").unwrap().length(),
    3000000000L,
  )
}
