///|
test "canonical JSON sorts object keys and keeps exact large integers" {
  let input = @utf8.encode(
    "{ \"z\": [true, 9007199254740993], \"a\": {\"b\":null,\"a\":\"x\"} }",
  )
  let value = parse(input).unwrap()
  let encoded = @utf8.decode(canonical(value)) catch {
    _ => abort("invalid UTF-8")
  }
  assert_eq(
    encoded, "{\"a\":{\"a\":\"x\",\"b\":null},\"z\":[true,9007199254740993]}",
  )
}

///|
test "canonical JSON normalizes escaped keys and string quotes" {
  let input = @utf8.encode("{\"\\u0062\":\"a\\\"b\\\\c\",\"a\":1}")
  let value = parse(input).unwrap()
  let encoded = @utf8.decode(canonical(value)) catch {
    _ => abort("invalid UTF-8")
  }
  assert_eq(encoded, "{\"a\":1,\"b\":\"a\\\"b\\\\c\"}")
}

///|
test "canonical JSON uses UTF-8 key ordering" {
  let input = @utf8.encode("{\"é\":1,\"z\":2,\"a\":3}")
  let value = parse(input).unwrap()
  let encoded = @utf8.decode(canonical(value)) catch {
    _ => abort("invalid UTF-8")
  }
  assert_eq(encoded, "{\"a\":3,\"z\":2,\"é\":1}")
}
