///|
test "shell paths support unicode classes ranges negation slash and literal brackets" {
  for
    (pattern, value, expected) in [
      ("plugins/*", "plugins/team/demo.wasm", false),
      ("[ab]?.bin", "aé.bin", true),
      ("[!a-c]*", "d/test", false),
      ("[!a-c]*", "b/test", false),
      ("[0-9].bin", "7.bin", true),
      ("[0-9].bin", "x.bin", false),
      ("[[]x", "[x", true),
      ("[]]", "]", true),
      ("[", "[", true),
      ("a*", "a/b/c", false),
      ("?", "中", true),
      ("?", "éé", false),
    ] {
    assert_eq(@model.path_pattern_matches(pattern, value), expected)
  }
}

///|
test "succinct roles select only the correct 1 to 32 bit hash bin" {
  let key = @testkit.signer(236)
  let base = @testkit.top_with_delegation(1, "apps", "*", key, key)
  let envelope = @model.parse_envelope(base).unwrap()
  let role = "{\"keyids\":[\"\{key.keyid()}\"],\"threshold\":1,\"bit_length\":32,\"name_prefix\":\"bins\"}"
  let role_value = @wire.parse(@utf8.encode(role)).unwrap()
  let raw = envelope.signed()
  let entries = raw.as_dict().unwrap()
  for i = 0; i < entries.length(); i = i + 1 {
    if entries[i].0 == "delegations" {
      let existing = entries[i].1
      entries[i] = (
        "delegations",
        @wire.Dict([
          ("keys", existing.field("keys").unwrap()),
          ("succinct_roles", role_value),
        ]),
      )
    }
  }
  let body = try! @utf8.decode(@wire.canonical(@wire.Dict(entries)))
  let targets = @model.parse_targets(@testkit.signed_envelope(body, [key])).unwrap()
  let succinct = targets.delegations().unwrap().succinct_roles().unwrap()
  let selected = succinct.role_for_path("plugins/a.bin")
  let digest = @crypto.sha256_hex(@utf8.encode("plugins/a.bin"))
  assert_eq(selected.name(), "bins-" + digest[0:8].to_owned())
  assert_true(selected.terminating())
  assert_eq(succinct.bit_length(), 32)
  assert_eq(succinct.name_prefix(), "bins")
  assert_eq(
    targets.delegations().unwrap().roles_for_path("plugins/a.bin").length(),
    1,
  )
}
