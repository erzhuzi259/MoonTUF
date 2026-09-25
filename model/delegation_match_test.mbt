///|
test "path glob wildcard does not cross directory boundaries" {
  assert_true(path_pattern_matches("apps/*.tgz", "apps/demo.tgz"))
  assert_false(path_pattern_matches("apps/*.tgz", "apps/nested/demo.tgz"))
  assert_false(path_pattern_matches("*.tgz", "apps/demo.tgz"))
  assert_true(path_pattern_matches("app-?.tgz", "app-2.tgz"))
  assert_false(path_pattern_matches("app-?.tgz", "app-12.tgz"))
  assert_true(path_pattern_matches("a**b", "ab"))
  assert_true(path_pattern_matches("a**b", "axxb"))
  assert_false(path_pattern_matches("a**b", "a/x/b"))
}

///|
test "path pattern bounds prevent adversarial matcher memory growth" {
  let huge = "a".repeat(1025)
  assert_false(path_pattern_matches(huge, "a"))
  assert_false(path_pattern_matches("a*", "b".repeat(4097)))
}
