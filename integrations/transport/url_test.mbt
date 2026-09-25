///|
test "repository URL builder encodes reserved target bytes" {
  let urls = repository_urls(
    "https://updates.example.org/metadata/", "https://updates.example.org/targets/",
  ).unwrap()
  assert_eq(
    urls.metadata_url("2.snapshot.json").unwrap(),
    "https://updates.example.org/metadata/2.snapshot.json",
  )
  assert_eq(
    urls.target_url("plugins/a b?#%.wasm").unwrap(),
    "https://updates.example.org/targets/plugins/a%20b%3F%23%25.wasm",
  )
}

///|
test "repository URL builder rejects ambiguous bases and paths" {
  assert_true(
    repository_urls("http://example.org/meta", "https://example.org/t")
    is Err(InvalidBase(_)),
  )
  assert_true(
    repository_urls("https://user@example.org/m", "https://example.org/t")
    is Err(InvalidBase(_)),
  )
  assert_true(
    repository_urls("https://example.org/../m", "https://example.org/t")
    is Err(InvalidBase(_)),
  )
  let urls = repository_urls("https://example.org/m", "https://example.org/t").unwrap()
  assert_true(urls.metadata_url("../root.json") is Err(InvalidMetadataName(_)))
  assert_true(urls.metadata_url("timestamp.txt") is Err(InvalidMetadataName(_)))
  assert_true(urls.target_url("a/../b") is Err(InvalidTargetName(_)))
}

///|
test "request hints meter metadata without trusting transport lengths" {
  let urls = repository_urls("https://example.org/m", "https://example.org/t").unwrap()
  let hint = urls.timestamp_request(4L).unwrap()
  assert_eq(hint.name(), "timestamp.json")
  assert_eq(hint.url(), "https://example.org/m/timestamp.json")
  assert_eq(hint.exact_bytes(), None)
  let meter = hint.meter()
  meter.consume(2L).unwrap()
  assert_eq(meter.remaining(), 2L)
  assert_true(meter.consume(3L) is Err(ResponseTooLarge(3L, 2L)))
  assert_true(meter.finish() is Err(RequestMeterClosed))
}

///|
test "request meter rejects negative sizes and double finish" {
  let urls = repository_urls("https://example.org/m", "https://example.org/t").unwrap()
  let meter = urls.timestamp_request(10L).unwrap().meter()
  assert_true(meter.consume(-1L) is Err(InvalidRequestBudget))
  assert_true(meter.consume(1L) is Err(RequestMeterClosed))
  let second = urls.timestamp_request(10L).unwrap().meter()
  second.consume(3L).unwrap()
  assert_eq(second.finish().unwrap(), 3L)
  assert_true(second.finish() is Err(RequestMeterClosed))
}

///|
test "request preflight rejects redirects and compressed responses" {
  let urls = repository_urls("https://example.org/m", "https://example.org/t").unwrap()
  let hint = urls.timestamp_request(10L).unwrap()
  assert_true(
    hint.check_response(302, None, "") is Err(UnexpectedHttpStatus(302)),
  )
  assert_true(
    hint.check_response(200, None, "gzip") is Err(UnsupportedContentEncoding),
  )
  assert_true(
    hint.check_response(200, Some(11L), "identity")
    is Err(ResponseTooLarge(11L, 10L)),
  )
  assert_true(hint.check_response(200, Some(5L), "identity") is Ok(_))
}
