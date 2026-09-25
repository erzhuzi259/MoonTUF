///|
fn admission_client(
  key : @testkit.Signer,
  path : String,
  artifact : Bytes,
) -> @client.Client {
  let targets = @testkit.targets(1, path, artifact, key)
  let snapshot = @testkit.snapshot(1, 1, targets, key)
  let timestamp = @testkit.timestamp(1, 1, snapshot, key)
  @client.open_trusted_root(
    @testkit.root(1, key, [key], consistent_snapshot=true),
    "2026-09-25T00:00:00Z",
  )
  .unwrap()
  .accept_timestamp(timestamp)
  .unwrap()
  .accept_snapshot(snapshot)
  .unwrap()
  .accept_targets(targets)
  .unwrap()
}

///|
test "plugin namespace policy creates a verifiable download ticket" {
  let key = @testkit.signer(41)
  let artifact = @utf8.encode("abc")
  let client = admission_client(key, "plugins/editor.bin", artifact)
  let rules = policy(prefix="plugins", max_bytes=16L, allowed_final_roles=[
    "targets",
  ]).unwrap()
  let no_delegations = fn(_ : String) -> Bytes? { None }
  let decision = evaluate(client, "plugins/editor.bin", rules, no_delegations).unwrap()
  match decision {
    Download(ticket) => {
      assert_eq(ticket.length(), 3L)
      assert_eq(ticket.target_role_chain(), ["targets"])
      assert_true(ticket.repository_name().has_prefix("plugins/ba7816"))
      assert_eq(
        verify_download(client, ticket, artifact, no_delegations)
        .unwrap()
        .length(),
        3L,
      )
    }
    Current => abort("new plugin unexpectedly current")
  }
}

///|
test "same installed hash is current and policy cannot escape namespace" {
  let key = @testkit.signer(42)
  let artifact = @utf8.encode("abc")
  let client = admission_client(key, "models/weights.bin", artifact)
  let rules = policy(prefix="models", max_bytes=16L).unwrap()
  let no_delegations = fn(_ : String) -> Bytes? { None }
  assert_true(
    evaluate(
      client,
      "models/weights.bin",
      rules,
      no_delegations,
      installed_sha256="BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
    )
    is Ok(Current),
  )
  assert_true(
    evaluate(client, "plugins/editor.bin", rules, no_delegations)
    is Err(OutsideNamespace(_)),
  )
}

///|
test "policy byte cap applies before download" {
  let key = @testkit.signer(43)
  let client = admission_client(
    key,
    "firmware/controller.bin",
    @utf8.encode("abc"),
  )
  let rules = policy(prefix="firmware", max_bytes=2L).unwrap()
  let no_delegations = fn(_ : String) -> Bytes? { None }
  assert_true(
    evaluate(client, "firmware/controller.bin", rules, no_delegations)
    is Err(TooLarge(3L, 2L)),
  )
}

///|
test "policy rejects malformed configuration" {
  assert_true(policy(prefix="../wrong") is Err(InvalidPolicy(_)))
  assert_true(policy(max_bytes=0L) is Err(InvalidPolicy(_)))
  assert_true(policy(allowed_final_roles=["../role"]) is Err(InvalidPolicy(_)))
}
