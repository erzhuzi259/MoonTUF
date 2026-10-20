// Generated from original inputs using securesystemslib 1.5.1 / cryptography 50.0.2.

///|
test "Python ed25519 signature and malformed-input isolation" {
  let key = "a7a3cbc20328b37da6f9d244c59e81fca73c24e84a31fbb7e302c5c04fd13f3e"
  let signature = "13bbf4690f3fba45513d64d0e183f0cde756e013aeb39b42ced60591ab3d36ad4eb6ca4ee41eaa1a01e0ea34636c29aef46d4f56b14b05982bba1effda63cf07"
  assert_true(@crypto.valid_public_key("ed25519", "ed25519", key))
  assert_true(
    @crypto.verify_signature(
      "ed25519",
      "ed25519",
      key,
      @crypto.decode_hex("4d6f6f6e545546207265666572656e636520c3a90a").unwrap(),
      signature,
    ).unwrap(),
  )
  assert_false(
    @crypto.verify_signature("ed25519", "ed25519", key, b"tampered", signature).unwrap(),
  )
  assert_false(@crypto.valid_public_key("ed25519", "ed25519", "malformed"))
}

///|
test "Python rsa signature and malformed-input isolation" {
  let key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvw2yS/6cNe6gB73gD94Z\nma3NnstoHxNoPG/9O84BiF7uWTzUDGZrvFvMIIRsUKyqzVlaBSBZq3o2/m8BED9L\nFyXI6I25LRLcs+J/Mywsg0MP2QFqBstJycbvUv1Nqy1q9iH3CSChAE5p3pQa9RoW\ngFdC0SQcAj87fFU5IN0cJxAlCvnh6kpLWKcxsbli12b59exh9/rVDiigqrcAiPCx\nU9S4hO5K6WQOSkKrBD6DYYlDR7c9uvXxN8do5tCXmP6ySmJJRSIsgHPj1LNu143w\nLcQsgGkKxb01MYKgZlAyYWB/Dvh76qqaYIPpvAahEIv5F5fyVsUwtTm4GBf1St9D\nvQIDAQAB\n-----END PUBLIC KEY-----\n"
  let signature = "7b7849d1d3e8b45a66b3a76d6ce54e4eea357e4373dd546d77267a845b0a9a6102e7438353a910eef0042fce5e5881533801783e940fb00bb07fb5abf12c5b39c340850c2c393206ced5bcd00a2e030f1857bb833889996cd120a8de7b4818b2e12bd941cbf0069c78913a673014c5f2146a740396d4b6ece59320237eb9d7b4b19ddfe05b75381b35cc40f777d857371197f8cd3c382c1d8e0cf4cf1f1805bad84707c02e781cbd0610061e3b220205c9a94a440c0618e263d20a8300c7db38177f7685d666b7051109904d49983336f332496e879d603d4fdb2e602ceb3c439ee8eaabdf0a65505bac80b0d30ef01d65bee71c3eb29f948bef77349868778d"
  assert_true(@crypto.valid_public_key("rsa", "rsassa-pss-sha256", key))
  assert_true(
    @crypto.verify_signature(
      "rsa",
      "rsassa-pss-sha256",
      key,
      @crypto.decode_hex("4d6f6f6e545546207265666572656e636520c3a90a").unwrap(),
      signature,
    ).unwrap(),
  )
  assert_false(
    @crypto.verify_signature(
      "rsa", "rsassa-pss-sha256", key, b"tampered", signature,
    ).unwrap(),
  )
  assert_false(
    @crypto.valid_public_key("rsa", "rsassa-pss-sha256", "malformed"),
  )
}

///|
test "Python ecdsa signature and malformed-input isolation" {
  let key = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEq8vnRdDLcpA5D6BoUMYlHY686cmU\ngGOze3sRa58cW2hcuF5G55UeqCfLBuCakwgei5JzCDCmId+j0GjeNvOMXw==\n-----END PUBLIC KEY-----\n"
  let signature = "3045022076dbb10631d0cb8969aab4e1dbb8835446a31ced9d806c27f04740d98bd100e0022100ce4c166583190c95243f081fb8374815e2ec7c90a6315d219bb93308af0d03e8"
  assert_true(@crypto.valid_public_key("ecdsa", "ecdsa-sha2-nistp256", key))
  assert_true(
    @crypto.verify_signature(
      "ecdsa",
      "ecdsa-sha2-nistp256",
      key,
      @crypto.decode_hex("4d6f6f6e545546207265666572656e636520c3a90a").unwrap(),
      signature,
    ).unwrap(),
  )
  assert_false(
    @crypto.verify_signature(
      "ecdsa", "ecdsa-sha2-nistp256", key, b"tampered", signature,
    ).unwrap(),
  )
  assert_false(
    @crypto.valid_public_key("ecdsa", "ecdsa-sha2-nistp256", "malformed"),
  )
}
