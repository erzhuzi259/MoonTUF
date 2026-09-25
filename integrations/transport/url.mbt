///|
/// URL construction is separate from networking. The host may pass these
/// addresses to its HTTP client, but must still cap responses and verify
/// every returned metadata document or target before using it.
pub(all) enum UrlError {
  InvalidBase(String)
  InvalidMetadataName(String)
  InvalidTargetName(String)
  Client(@client.ClientError)
  RootChainFinished
  InvalidRequestBudget
  ResponseTooLarge(Int64, Int64)
  ResponseLengthMismatch(Int64, Int64)
  RequestMeterClosed
  UnexpectedHttpStatus(Int)
  UnsupportedContentEncoding
} derive(Debug)

///|
pub struct RepositoryUrls {
  metadata_base : String
  targets_base : String
}

///|
pub fn RepositoryUrls::metadata_base(self : RepositoryUrls) -> String {
  self.metadata_base
}

///|
pub fn RepositoryUrls::targets_base(self : RepositoryUrls) -> String {
  self.targets_base
}

///|
/// Only absolute HTTPS origin/path prefixes are accepted. A query, fragment,
/// userinfo or percent escape in the base would make joins ambiguous. Local
/// or offline transports can use request names without this helper.
pub fn repository_urls(
  metadata_base : String,
  targets_base : String,
) -> Result[RepositoryUrls, UrlError] {
  if !valid_base(metadata_base) {
    return Err(InvalidBase("metadata"))
  }
  if !valid_base(targets_base) {
    return Err(InvalidBase("targets"))
  }
  Ok({
    metadata_base: trim_slash(metadata_base),
    targets_base: trim_slash(targets_base),
  })
}

///|
fn trim_slash(value : String) -> String {
  if value.has_suffix("/") {
    value[:value.length() - 1].to_owned()
  } else {
    value
  }
}

///|
fn valid_base(value : String) -> Bool {
  if !value.has_prefix("https://") || value.length() > 2048 {
    return false
  }
  let rest = value[8:].to_owned()
  let authority = rest.split("/").next().unwrap_or("")
  if authority == "" || authority.contains("@") || authority.contains(":") {
    return false
  }
  let bytes = @utf8.encode(value)
  for byte in bytes {
    let n = byte.to_int()
    if n < 33 || n > 126 || n == 37 || n == 35 || n == 63 || n == 92 {
      return false
    }
  }
  let parts : Array[String] = rest
    .split("/")
    .map(part => part.to_owned())
    .collect()
  for index in 1..<parts.length() {
    let segment = parts[index]
    if segment == "." ||
      segment == ".." ||
      (segment == "" && index < parts.length() - 1) {
      return false
    }
  }
  true
}

///|
fn hex_digit(value : Int) -> String {
  let digits = "0123456789ABCDEF"
  digits[value:value + 1].to_owned()
}

///|
fn unreserved(value : Int) -> Bool {
  (value >= 65 && value <= 90) ||
  (value >= 97 && value <= 122) ||
  (value >= 48 && value <= 57) ||
  value == 45 ||
  value == 46 ||
  value == 95 ||
  value == 126
}

///|
/// Encode UTF-8 bytes, not Unicode code points. A slash remains a path
/// separator; every literal '%' is escaped so it cannot become a second
/// path traversal or URL delimiter after decoding by an HTTP stack.
fn encoded_path(path : String) -> String {
  let output : Array[String] = []
  let bytes = @utf8.encode(path)
  for index in 0..<bytes.length() {
    let byte = bytes[index]
    let n = byte.to_int()
    if unreserved(n) || n == 47 {
      output.push(path[index:index + 1].to_owned())
    } else {
      output.push("%" + hex_digit(n / 16) + hex_digit(n % 16))
    }
  }
  output.join("")
}

///|
/// Convert the metadata request name returned by MoonTUF into an HTTPS URL.
/// Versioned and delegated names are both accepted, but traversal and
/// non-JSON files are rejected before URL construction.
pub fn RepositoryUrls::metadata_url(
  self : RepositoryUrls,
  request_name : String,
) -> Result[String, UrlError] {
  if !@model.safe_target_path(request_name) || !request_name.has_suffix(".json") {
    return Err(InvalidMetadataName(request_name))
  }
  Ok(self.metadata_base + "/" + encoded_path(request_name))
}

///|
/// Convert a trusted target request name (possibly hash-prefixed under
/// consistent snapshots) into an HTTPS URL. This URL itself does not attest
/// the target; the caller must verify the downloaded bytes through MoonTUF.
pub fn RepositoryUrls::target_url(
  self : RepositoryUrls,
  request_name : String,
) -> Result[String, UrlError] {
  if !@model.safe_target_path(request_name) {
    return Err(InvalidTargetName(request_name))
  }
  Ok(self.targets_base + "/" + encoded_path(request_name))
}
