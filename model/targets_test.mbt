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
test "target custom mutations do not alter descriptors or envelope payload" {
  let raw = @utf8.encode(
    "{\"signed\":{\"_type\":\"targets\",\"spec_version\":\"1.0.0\",\"version\":2,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{\"apps/demo.bin\":{\"length\":3,\"hashes\":{\"sha256\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"},\"custom\":{\"channels\":[{\"name\":\"stable\",\"architectures\":[\"x86_64\"]}]}}}},\"signatures\":[]}",
  )
  let targets = parse_targets(raw).unwrap()
  let descriptor = targets.target("apps/demo.bin").unwrap()
  let original_custom = @wire.canonical(descriptor.custom().unwrap())
  let original_signed = targets.envelope().canonical_signed()
  let exposed = descriptor.custom().unwrap()
  let channels = exposed.field("channels").unwrap().as_list().unwrap()
  let channel = channels[0].as_dict().unwrap()
  let architectures = channels[0]
    .field("architectures")
    .unwrap()
    .as_list()
    .unwrap()
  architectures[0] = Text("untrusted-architecture")
  channel[0] = ("name", Text("untrusted-channel"))
  channels.push(Text("injected"))
  assert_eq(architectures[0].as_text(), Some("untrusted-architecture"))
  assert_eq(channels.length(), 2)
  assert_eq(
    @wire.canonical(descriptor.custom().unwrap()).to_array(),
    original_custom.to_array(),
  )
  assert_eq(
    @wire.canonical(targets.target("apps/demo.bin").unwrap().custom().unwrap()).to_array(),
    original_custom.to_array(),
  )
  assert_eq(
    @wire.canonical(targets.envelope().signed()).to_array(),
    original_signed.to_array(),
  )
  assert_eq(targets.envelope().raw().to_array(), raw.to_array())
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
test "delegation parser retains order and rejects duplicate role names" {
  let public_hex = "0000000000000000000000000000000000000000000000000000000000000000"
  let key_json = "{\"keytype\":\"ed25519\",\"scheme\":\"ed25519\",\"keyval\":{\"public\":\"\{public_hex}\"}}"
  let key = @wire.parse(@utf8.encode(key_json)).unwrap()
  let keyid = @crypto.sha256_hex(@wire.canonical(key))
  let first = "{\"name\":\"plugins/a\",\"keyids\":[\"\{keyid}\"],\"threshold\":1,\"paths\":[\"plugins/*\"]}"
  let second = "{\"name\":\"plugins/b\",\"keyids\":[\"\{keyid}\"],\"threshold\":1,\"paths\":[\"plugins/*\"]}"
  let prefix = "{\"signed\":{\"_type\":\"targets\",\"spec_version\":\"1.0.0\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{},\"delegations\":{\"keys\":{\"\{keyid}\":\{key_json}},\"roles\":["
  let suffix = "]}},\"signatures\":[]}"
  let valid = @utf8.encode(prefix + first + "," + second + suffix)
  let roles = parse_targets(valid).unwrap().delegations().unwrap().roles()
  assert_eq(roles.length(), 2)
  assert_eq(roles[0].name(), "plugins/a")
  assert_eq(roles[1].name(), "plugins/b")
  let duplicate = @utf8.encode(
    prefix + first + "," + second + "," + first + suffix,
  )
  assert_true(parse_targets(duplicate) is Err(DuplicateItem(_)))
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
