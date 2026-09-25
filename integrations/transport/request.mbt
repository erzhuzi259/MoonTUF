///|
/// An HTTP request hint is not trusted content. The caller still obtains
/// bytes with its own transport, caps their actual length, and passes them
/// into the client for cryptographic verification. Hints keep the host's
/// fetch path and size limit aligned with the trust machine.
pub(all) enum RequestKind {
  RootMetadata
  TimestampMetadata
  SnapshotMetadata
  TargetsMetadata
  TargetFile
} derive(Debug)

///|
pub struct RequestHint {
  kind : RequestKind
  name : String
  url : String
  max_bytes : Int64
  exact_bytes : Int64?
  sha256 : String?
}

///|
pub fn RequestHint::kind(self : RequestHint) -> RequestKind {
  self.kind
}

///|
pub fn RequestHint::name(self : RequestHint) -> String {
  self.name
}

///|
pub fn RequestHint::url(self : RequestHint) -> String {
  self.url
}

///|
pub fn RequestHint::max_bytes(self : RequestHint) -> Int64 {
  self.max_bytes
}

///|
pub fn RequestHint::exact_bytes(self : RequestHint) -> Int64? {
  self.exact_bytes
}

///|
pub fn RequestHint::sha256(self : RequestHint) -> String? {
  self.sha256
}

///|
fn metadata_hint(
  urls : RepositoryUrls,
  kind : RequestKind,
  name : String,
  maximum : Int64,
) -> Result[RequestHint, UrlError] {
  if maximum < 1L {
    return Err(InvalidRequestBudget)
  }
  let url = match urls.metadata_url(name) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  Ok({ kind, name, url, max_bytes: maximum, exact_bytes: None, sha256: None, })
}

///|
pub fn RepositoryUrls::next_root_request(
  self : RepositoryUrls,
  client : @client.Client,
  maximum : Int64,
) -> Result[RequestHint, UrlError] {
  let name = match client.next_root_name() {
    Some(value) => value
    None => return Err(RootChainFinished)
  }
  metadata_hint(self, RootMetadata, name, maximum)
}

///|
pub fn RepositoryUrls::timestamp_request(
  self : RepositoryUrls,
  maximum : Int64,
) -> Result[RequestHint, UrlError] {
  metadata_hint(self, TimestampMetadata, "timestamp.json", maximum)
}

///|
pub fn RepositoryUrls::snapshot_request(
  self : RepositoryUrls,
  client : @client.Client,
  maximum : Int64,
) -> Result[RequestHint, UrlError] {
  let name = match client.snapshot_request_name() {
    Ok(value) => value
    Err(error) => return Err(Client(error))
  }
  metadata_hint(self, SnapshotMetadata, name, maximum)
}

///|
pub fn RepositoryUrls::targets_request(
  self : RepositoryUrls,
  client : @client.Client,
  maximum : Int64,
) -> Result[RequestHint, UrlError] {
  let name = match client.targets_request_name() {
    Ok(value) => value
    Err(error) => return Err(Client(error))
  }
  metadata_hint(self, TargetsMetadata, name, maximum)
}

///|
/// Turn an admission ticket into a bounded target fetch hint. The exact
/// digest and length are copied from trusted metadata, but are meaningful
/// only while the same client state remains in force.
pub fn RepositoryUrls::target_request(
  self : RepositoryUrls,
  ticket : @admission.Ticket,
) -> Result[RequestHint, UrlError] {
  let name = ticket.repository_name()
  let url = match self.target_url(name) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  Ok({
    kind: TargetFile,
    name,
    url,
    max_bytes: ticket.length(),
    exact_bytes: Some(ticket.length()),
    sha256: Some(ticket.sha256()),
  })
}

///|
/// A transport can meter each read before buffering it. This is only a
/// resource guard: it cannot replace the client's signature or hash checks.
pub struct RequestMeter {
  maximum : Int64
  exact : Int64?
  mut seen : Int64
  mut closed : Bool
}

///|
pub fn RequestHint::meter(self : RequestHint) -> RequestMeter {
  { maximum: self.max_bytes, exact: self.exact_bytes, seen: 0L, closed: false, }
}

///|
pub fn RequestMeter::bytes_seen(self : RequestMeter) -> Int64 {
  self.seen
}

///|
pub fn RequestMeter::remaining(self : RequestMeter) -> Int64 {
  self.maximum - self.seen
}

///|
/// Consume a nonnegative chunk length. Subtraction avoids integer overflow
/// when a malicious server reports an extreme Content-Length or chunk size.
pub fn RequestMeter::consume(
  self : RequestMeter,
  chunk_length : Int64,
) -> Result[Unit, UrlError] {
  if self.closed {
    return Err(RequestMeterClosed)
  }
  if chunk_length < 0L {
    self.closed = true
    return Err(InvalidRequestBudget)
  }
  if chunk_length > self.maximum - self.seen {
    self.closed = true
    return Err(ResponseTooLarge(chunk_length, self.maximum - self.seen))
  }
  self.seen += chunk_length
  Ok(())
}

///|
/// Finish length accounting. A target's exact length is checked here for
/// early failure and checked again when its cryptographic stream finishes.
pub fn RequestMeter::finish(self : RequestMeter) -> Result[Int64, UrlError] {
  if self.closed {
    return Err(RequestMeterClosed)
  }
  self.closed = true
  match self.exact {
    Some(expected) =>
      if self.seen != expected {
        Err(ResponseLengthMismatch(expected, self.seen))
      } else {
        Ok(self.seen)
      }
    None => Ok(self.seen)
  }
}
