///|
/// Compare decoded object keys in UTF-8 byte order for the selected JSON POUF.
/// This intentionally avoids locale-sensitive or UTF-16 collation.
fn compare_keys(left : String, right : String) -> Int {
  let a = @utf8.encode(left)
  let b = @utf8.encode(right)
  let common = if a.length() < b.length() { a.length() } else { b.length() }
  for index in 0..<common {
    let x = a[index].to_int()
    let y = b[index].to_int()
    if x < y {
      return -1
    }
    if x > y {
      return 1
    }
  }
  if a.length() < b.length() {
    -1
  } else if a.length() > b.length() {
    1
  } else {
    0
  }
}

///|
fn push_ascii(output : Array[Byte], text : String) -> Unit {
  for byte in @utf8.encode(text) {
    output.push(byte)
  }
}

///|
/// OLPC canonical JSON escapes only quote and backslash. Other bytes,
/// including controls, are emitted as-is by that specific signature format.
fn push_string(output : Array[Byte], text : String) -> Unit {
  output.push(34)
  for byte in @utf8.encode(text) {
    if byte.to_int() == 34 || byte.to_int() == 92 {
      output.push(92)
    }
    output.push(byte)
  }
  output.push(34)
}

///|
fn append_canonical(value : Value, output : Array[Byte]) -> Unit {
  match value {
    Null => push_ascii(output, "null")
    Boolean(flag) => push_ascii(output, if flag { "true" } else { "false" })
    Integer(lexeme) => push_ascii(output, lexeme)
    Text(text) => push_string(output, text)
    List(items) => {
      output.push(91)
      for index in 0..<items.length() {
        if index > 0 {
          output.push(44)
        }
        append_canonical(items[index], output)
      }
      output.push(93)
    }
    Dict(entries) => {
      let order : Array[Int] = []
      for index in 0..<entries.length() {
        order.push(index)
      }
      order.sort_by(fn(left, right) {
        let (a, _) = entries[left]
        let (b, _) = entries[right]
        compare_keys(a, b)
      })
      output.push(123)
      for position in 0..<order.length() {
        if position > 0 {
          output.push(44)
        }
        let (key, child) = entries[order[position]]
        push_string(output, key)
        output.push(58)
        append_canonical(child, output)
      }
      output.push(125)
    }
  }
}

///|
/// Return the exact bytes to be signed or verified for a `signed` document.
/// Only call this on values returned by `parse`, which guarantees unique keys
/// and canonical integer syntax.
pub fn canonical(value : Value) -> Bytes {
  let output : Array[Byte] = []
  append_canonical(value, output)
  Bytes::from_array(output)
}
