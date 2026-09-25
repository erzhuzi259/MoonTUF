///|
test "hex rejects malformed input and round-trips bytes" {
  assert_true(decode_hex("abc") is Err(OddHexLength(3)))
  assert_true(decode_hex("00xz") is Err(InvalidHexDigit(2)))
  assert_eq(encode_hex(Bytes::from_array([0, 1, 127, 255])), "00017fff")
}

///|
test "SHA-256 known answer and digest matching" {
  let bytes = @utf8.encode("abc")
  let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  assert_eq(sha256_hex(bytes), expected)
  assert_true(matches_sha256(bytes, expected))
  assert_false(matches_sha256(@utf8.encode("abd"), expected))
}

///|
test "Ed25519 rejects malformed public material" {
  let message = @utf8.encode("abc")
  assert_true(
    verify_ed25519("00", message, "00") is Err(InvalidPublicKeyLength(1)),
  )
}

///|
/// RFC 8032 section 7.1, Ed25519 TEST 1. Unlike the synthetic TUF fixtures,
/// this public known-answer vector was not produced by mooncrypt's signer.
test "Ed25519 verifies independent RFC 8032 known answer" {
  let public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
  let signature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
  assert_true(
    verify_ed25519(public_key, @utf8.encode(""), signature) is Ok(true),
  )
  assert_true(
    verify_ed25519(public_key, @utf8.encode("x"), signature) is Ok(false),
  )
}
