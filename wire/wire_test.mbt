///|
test "signed JSON keeps exact integer spelling and decoded object key" {
  let parsed = parse(@utf8.encode("{\"z\":9007199254740993,\"a\":\"ok\"}"))
  match parsed {
    Ok(value) => {
      assert_eq(value.field("z").unwrap().as_integer().unwrap(), "9007199254740993")
      assert_eq(value.field("a").unwrap().as_text().unwrap(), "ok")
    }
    Err(_) => abort("valid TUF JSON was rejected")
  }
}

///|
test "duplicate keys include equivalent Unicode spellings" {
  let parsed = parse(@utf8.encode("{\"a\":1,\"\\u0061\":2}"))
  match parsed {
    Err(DuplicateKey(name)) => assert_eq(name, "a")
    _ => abort("duplicate object key was accepted")
  }
}

///|
test "noninteger and ambiguous integers are rejected" {
  assert_true(parse(@utf8.encode("1.25")) is Err(NonIntegerNumber(_)))
  assert_true(parse(@utf8.encode("1e9")) is Err(NonIntegerNumber(_)))
  assert_true(parse(@utf8.encode("-0")) is Err(InvalidJson(_, _)))
  assert_true(parse(@utf8.encode("012")) is Err(InvalidJson(_, _)))
}

///|
test "resource budgets apply to bytes, depth and nodes" {
  assert_true(
    parse(@utf8.encode("[1]"), limits=limits(max_bytes=2)) is
    Err(InputTooLarge(_, _)),
  )
  assert_true(
    parse(@utf8.encode("[[1]]"), limits=limits(max_depth=1)) is
    Err(NestingTooDeep(_)),
  )
  assert_true(
    parse(@utf8.encode("[1,2]"), limits=limits(max_nodes=2)) is
    Err(TooManyNodes(_)),
  )
}

///|
test "truncated, trailing and malformed JSON are rejected" {
  assert_true(parse(@utf8.encode("{\"x\":1,")) is Err(InvalidJson(_, _)))
  assert_true(parse(@utf8.encode("[1,]")) is Err(InvalidJson(_, _)))
  assert_true(parse(@utf8.encode("true false")) is Err(InvalidJson(_, _)))
  assert_true(parse(@utf8.encode("\"\\x\"")) is Err(InvalidJson(_, _)))
}
