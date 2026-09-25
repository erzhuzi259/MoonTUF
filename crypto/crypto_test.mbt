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
