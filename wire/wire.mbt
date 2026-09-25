///|
/// TUF's signed JSON is deliberately narrower than general JSON: all numbers
/// are integers and their original spelling must remain exact. A dedicated AST
/// avoids floating-point round trips in versions, lengths and canonical bytes.
pub(all) enum Value {
  Null
  Boolean(Bool)
  Integer(String)
  Text(String)
  List(Array[Value])
  Dict(Array[(String, Value)])
} derive(Debug)

///|
pub(all) enum WireError {
  InputTooLarge(Int, Int)
  NestingTooDeep(Int)
  TooManyNodes(Int)
  TooManyMembers(Int)
  NumberTooLong(Int)
  InvalidJson(Int, String)
  DuplicateKey(String)
  NonIntegerNumber(Int)
} derive(Debug, Eq)

///|
pub struct Limits {
  max_bytes : Int
  max_depth : Int
  max_nodes : Int
  max_members : Int
  max_number_digits : Int
}

///|
/// Construct limits for untrusted metadata. A hard depth cap prevents a caller
/// accidentally asking the recursive parser to exhaust the native stack.
pub fn limits(
  max_bytes? : Int = 1024 * 1024,
  max_depth? : Int = 64,
  max_nodes? : Int = 100000,
  max_members? : Int = 10000,
  max_number_digits? : Int = 80,
) -> Limits {
  {
    max_bytes: if max_bytes < 0 { 0 } else { max_bytes },
    max_depth: if max_depth < 0 { 0 } else if max_depth > 256 { 256 } else { max_depth },
    max_nodes: if max_nodes < 0 { 0 } else { max_nodes },
    max_members: if max_members < 0 { 0 } else { max_members },
    max_number_digits: if max_number_digits < 1 { 1 } else if max_number_digits > 1000 {
      1000
    } else { max_number_digits },
  }
}

///|
pub fn Limits::max_bytes(self : Limits) -> Int { self.max_bytes }

///|
pub fn Limits::max_depth(self : Limits) -> Int { self.max_depth }

///|
pub fn Limits::max_nodes(self : Limits) -> Int { self.max_nodes }

///|
priv struct Parser {
  data : Bytes
  limits : Limits
  mut nodes : Int
}

///|
fn Parser::at(self : Parser, offset : Int, ch : Int) -> Bool {
  offset < self.data.length() && self.data[offset].to_int() == ch
}

///|
fn Parser::space(self : Parser, start : Int) -> Int {
  let mut cursor = start
  while cursor < self.data.length() {
    let ch = self.data[cursor].to_int()
    if ch == 32 || ch == 10 || ch == 13 || ch == 9 {
      cursor += 1
    } else {
      break
    }
  }
  cursor
}

///|
fn Parser::read_string(
  self : Parser,
  start : Int,
) -> Result[(String, Int), WireError] {
  if !self.at(start, 34) {
    return Err(InvalidJson(start, "expected quoted string"))
  }
  let mut cursor = start + 1
  while cursor < self.data.length() {
    let ch = self.data[cursor].to_int()
    if ch == 34 {
      let raw = Bytes::from_array(self.data[start:cursor + 1].to_array())
      let token = @utf8.decode(raw) catch {
        _ => return Err(InvalidJson(start, "invalid UTF-8 string"))
      }
      let decoded : Json = @json.parse(token) catch {
        _ => return Err(InvalidJson(start, "invalid JSON string escape"))
      }
      return match decoded {
        String(value) => Ok((value, cursor + 1))
        _ => Err(InvalidJson(start, "expected JSON string"))
      }
    }
    if ch < 32 {
      return Err(InvalidJson(cursor, "unescaped control byte in string"))
    }
    if ch == 92 {
      cursor += 1
      if cursor >= self.data.length() {
        return Err(InvalidJson(cursor, "truncated string escape"))
      }
    }
    cursor += 1
  }
  Err(InvalidJson(start, "unterminated string"))
}

///|
fn digit(ch : Int) -> Bool { ch >= 48 && ch <= 57 }

///|
fn Parser::read_integer(
  self : Parser,
  start : Int,
) -> Result[(Value, Int), WireError] {
  let mut cursor = start
  if self.at(cursor, 45) { cursor += 1 }
  if cursor >= self.data.length() || !digit(self.data[cursor].to_int()) {
    return Err(InvalidJson(cursor, "expected integer digits"))
  }
  if self.at(cursor, 48) {
    cursor += 1
    if cursor < self.data.length() && digit(self.data[cursor].to_int()) {
      return Err(InvalidJson(cursor, "leading zero in integer"))
    }
    if start < cursor - 1 && self.at(cursor - 1, 48) {
      return Err(InvalidJson(start, "negative zero is not canonical"))
    }
  } else {
    while cursor < self.data.length() && digit(self.data[cursor].to_int()) {
      cursor += 1
    }
  }
  if cursor - start > self.limits.max_number_digits {
    return Err(NumberTooLong(cursor - start))
  }
  if cursor < self.data.length() {
    let ch = self.data[cursor].to_int()
    if ch == 46 || ch == 69 || ch == 101 {
      return Err(NonIntegerNumber(cursor))
    }
  }
  let raw = Bytes::from_array(self.data[start:cursor].to_array())
  let lexeme = @utf8.decode(raw) catch {
    _ => return Err(InvalidJson(start, "invalid integer encoding"))
  }
  Ok((Integer(lexeme), cursor))
}

///|
fn Parser::literal(
  self : Parser,
  start : Int,
  word : String,
  value : Value,
) -> Result[(Value, Int), WireError] {
  let bytes = @utf8.encode(word)
  if start + bytes.length() > self.data.length() {
    return Err(InvalidJson(start, "truncated literal"))
  }
  for index in 0..<bytes.length() {
    if self.data[start + index] != bytes[index] {
      return Err(InvalidJson(start + index, "invalid literal"))
    }
  }
  Ok((value, start + bytes.length()))
}

///|
fn Parser::value(
  self : Parser,
  start : Int,
  depth : Int,
) -> Result[(Value, Int), WireError] {
  if depth > self.limits.max_depth {
    return Err(NestingTooDeep(depth))
  }
  self.nodes += 1
  if self.nodes > self.limits.max_nodes {
    return Err(TooManyNodes(self.nodes))
  }
  let cursor = self.space(start)
  if cursor >= self.data.length() {
    return Err(InvalidJson(cursor, "missing value"))
  }
  let ch = self.data[cursor].to_int()
  if ch == 123 {
    self.object(cursor, depth + 1)
  } else if ch == 91 {
    self.array(cursor, depth + 1)
  } else if ch == 34 {
    match self.read_string(cursor) {
      Ok((text, end)) => Ok((Text(text), end))
      Err(error) => Err(error)
    }
  } else if ch == 116 {
    self.literal(cursor, "true", Boolean(true))
  } else if ch == 102 {
    self.literal(cursor, "false", Boolean(false))
  } else if ch == 110 {
    self.literal(cursor, "null", Null)
  } else if ch == 45 || digit(ch) {
    self.read_integer(cursor)
  } else {
    Err(InvalidJson(cursor, "unexpected value token"))
  }
}

///|
fn Parser::object(
  self : Parser,
  start : Int,
  depth : Int,
) -> Result[(Value, Int), WireError] {
  let entries : Array[(String, Value)] = []
  let names : Array[String] = []
  let mut cursor = self.space(start + 1)
  if self.at(cursor, 125) {
    return Ok((Dict(entries), cursor + 1))
  }
  while cursor < self.data.length() {
    if entries.length() >= self.limits.max_members {
      return Err(TooManyMembers(entries.length() + 1))
    }
    let (name, after_name) = match self.read_string(cursor) {
      Ok(pair) => pair
      Err(error) => return Err(error)
    }
    if names.contains(name) {
      return Err(DuplicateKey(name))
    }
    names.push(name)
    cursor = self.space(after_name)
    if !self.at(cursor, 58) {
      return Err(InvalidJson(cursor, "missing ':' after object key"))
    }
    let (child, after_child) = match self.value(cursor + 1, depth) {
      Ok(pair) => pair
      Err(error) => return Err(error)
    }
    entries.push((name, child))
    cursor = self.space(after_child)
    if self.at(cursor, 125) {
      return Ok((Dict(entries), cursor + 1))
    }
    if !self.at(cursor, 44) {
      return Err(InvalidJson(cursor, "expected ',' or '}'"))
    }
    cursor = self.space(cursor + 1)
  }
  Err(InvalidJson(cursor, "unterminated object"))
}

///|
fn Parser::array(
  self : Parser,
  start : Int,
  depth : Int,
) -> Result[(Value, Int), WireError] {
  let entries : Array[Value] = []
  let mut cursor = self.space(start + 1)
  if self.at(cursor, 93) {
    return Ok((List(entries), cursor + 1))
  }
  while cursor < self.data.length() {
    if entries.length() >= self.limits.max_members {
      return Err(TooManyMembers(entries.length() + 1))
    }
    let (child, after_child) = match self.value(cursor, depth) {
      Ok(pair) => pair
      Err(error) => return Err(error)
    }
    entries.push(child)
    cursor = self.space(after_child)
    if self.at(cursor, 93) {
      return Ok((List(entries), cursor + 1))
    }
    if !self.at(cursor, 44) {
      return Err(InvalidJson(cursor, "expected ',' or ']'"))
    }
    cursor = self.space(cursor + 1)
  }
  Err(InvalidJson(cursor, "unterminated array"))
}

///|
/// Parse bounded TUF JSON. Duplicate keys and noninteger numbers are rejected
/// before any metadata object is allowed to reach signature verification.
pub fn parse(input : Bytes, limits? : Limits = limits()) -> Result[Value, WireError] {
  if input.length() > limits.max_bytes {
    return Err(InputTooLarge(input.length(), limits.max_bytes))
  }
  let parser = Parser::{ data: input, limits, nodes: 0 }
  let (parsed, end) = match parser.value(0, 0) {
    Ok(pair) => pair
    Err(error) => return Err(error)
  }
  let final_offset = parser.space(end)
  if final_offset != input.length() {
    Err(InvalidJson(final_offset, "trailing content"))
  } else {
    Ok(parsed)
  }
}

///|
pub fn Value::field(self : Value, name : String) -> Value? {
  match self {
    Dict(entries) => {
      for entry in entries {
        let (key, value) = entry
        if key == name { return Some(value) }
      }
      None
    }
    _ => None
  }
}

///|
pub fn Value::as_text(self : Value) -> String? {
  match self { Text(value) => Some(value); _ => None }
}

///|
pub fn Value::as_boolean(self : Value) -> Bool? {
  match self { Boolean(value) => Some(value); _ => None }
}

///|
pub fn Value::as_integer(self : Value) -> String? {
  match self { Integer(value) => Some(value); _ => None }
}

///|
pub fn Value::as_list(self : Value) -> Array[Value]? {
  match self { List(value) => Some(value); _ => None }
}

///|
pub fn Value::as_dict(self : Value) -> Array[(String, Value)]? {
  match self { Dict(value) => Some(value); _ => None }
}
