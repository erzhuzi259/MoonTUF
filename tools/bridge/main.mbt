///|
/// Synchronous pipe I/O only. Python owns bounded HTTP and disk operations;
/// every trust decision runs in the same MoonBit library used by consumers.
extern "js" fn exchange(text : String) -> String =
  #| (text) => {
  #|   const fs = require('node:fs');
  #|   if (text !== '') fs.writeSync(1, text + '\n');
  #|   const out = []; const byte = Buffer.alloc(1);
  #|   for (;;) { if (fs.readSync(0, byte, 0, 1, null) === 0) throw Error('closed bridge');
  #|     if (byte[0] === 10) break; out.push(byte[0]);
  #|     if (out.length > 100 * 1024 * 1024) throw Error('bridge line limit'); }
  #|   return Buffer.from(out).toString('utf8');
  #| }

///|
fn text(value : @wire.Value, name : String) -> String {
  match value.field(name) {
    Some(@wire.Text(value)) => value
    _ => ""
  }
}

///|
fn request(kind : String, name : String, maximum : Int64) -> @wire.Value {
  let encoded = @wire.canonical(
    @wire.Dict([
      ("fetch", @wire.Text(kind)),
      ("name", @wire.Text(name)),
      ("maximum", @wire.Text(maximum.to_string())),
    ]),
  )
  let response = exchange(
    @utf8.decode(encoded) catch {
      _ => abort("bridge utf8")
    },
  )
  @wire.parse(
    @utf8.encode(response),
    limits=@wire.limits(max_bytes=100 * 1024 * 1024),
  ).unwrap()
}

///|
fn load_metadata(name : String) -> @client.MetadataResponse {
  let value = request("metadata", name, 8L * 1024L * 1024L)
  match text(value, "status") {
    "present" =>
      match @crypto.decode_hex(text(value, "raw")) {
        Ok(bytes) => @client.MetadataPresent(bytes)
        _ => @client.MetadataFailure
      }
    "absent" => @client.MetadataAbsent
    _ => @client.MetadataFailure
  }
}

///|
fn fail(error : String, current : @client.Client?) -> Unit {
  let fields = [("ok", @wire.Boolean(false)), ("error", @wire.Text(error))]
  if current is Some(client) {
    fields.push(("state", @wire.Text(@crypto.encode_hex(client.save_state()))))
  }
  println(
    @utf8.decode(@wire.canonical(@wire.Dict(fields))) catch {
      _ => abort("utf8")
    },
  )
}

///|
fn main {
  let input = @wire.parse(
    @utf8.encode(exchange("")),
    limits=@wire.limits(max_bytes=100 * 1024 * 1024),
  ).unwrap()
  let root = @crypto.decode_hex(text(input, "root")).unwrap()
  let now = text(input, "time")
  let mut client = if text(input, "state") == "" {
    match @client.open_trusted_root(root, now) {
      Ok(value) => value
      Err(error) => {
        fail(error.to_repr().to_string(), None)
        return
      }
    }
  } else {
    match
      @client.restore_state(
        @crypto.decode_hex(text(input, "state")).unwrap(),
        root,
        now,
      ) {
      Ok(value) => value
      Err(error) => {
        fail(error.to_repr().to_string(), None)
        return
      }
    }
  }
  let outcome = client.refresh(load_metadata)
  client = outcome.client()
  if outcome.status() is @client.Failed(error) {
    fail(error.to_repr().to_string(), Some(client))
    return
  }
  if input.field("targets") is Some(@wire.List(targets)) {
    // Cache delegated bytes for this update: a role loaded once is still
    // re-authorized against the immediate parent on every lookup.
    let cache : Map[String, Bytes] = Map([])
    let load = fn(name) {
      match cache.get(name) {
        Some(bytes) => Some(bytes)
        None =>
          match load_metadata(name) {
            @client.MetadataPresent(bytes) => {
              cache[name] = bytes
              Some(bytes)
            }
            _ => None
          }
      }
    }
    for target in targets {
      let path = target.as_text().unwrap()
      let descriptor = match client.find_target(path, load) {
        Ok(value) => value
        Err(error) => {
          fail(error.to_repr().to_string(), Some(client))
          return
        }
      }
      let cached = request("cached", path, descriptor.length())
      let bytes = match @crypto.decode_hex(text(cached, "raw")) {
        Ok(value) => value
        _ => b""
      }
      if text(cached, "status") == "present" &&
        client.verify_target(path, bytes, load) is Ok(_) {
        continue
      }
      let name = client.target_request_name(path, load).unwrap()
      let response = request("target", name, descriptor.length())
      let bytes = match @crypto.decode_hex(text(response, "raw")) {
        Ok(value) => value
        _ => b""
      }
      if text(response, "status") != "present" {
        fail("target transport failed", Some(client))
        return
      }
      match client.verify_target(path, bytes, load) {
        Ok(_) => {
          let event = @wire.Dict([
            ("store", @wire.Text("target")),
            ("name", @wire.Text(path)),
            ("raw", @wire.Text(@crypto.encode_hex(bytes))),
          ])
          ignore(
            exchange(
              @utf8.decode(@wire.canonical(event)) catch {
                _ => abort("utf8")
              },
            ),
          )
        }
        Err(error) => {
          fail(error.to_repr().to_string(), Some(client))
          return
        }
      }
    }
  }
  let result = @wire.Dict([
    ("ok", @wire.Boolean(true)),
    ("state", @wire.Text(@crypto.encode_hex(client.save_state()))),
  ])
  println(@utf8.decode(@wire.canonical(result)) catch { _ => abort("utf8") })
}
