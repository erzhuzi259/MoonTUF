///|
fn ascii_digit(text : String, start : Int, count : Int) -> Int? {
  let bytes = @utf8.encode(text)
  if start < 0 || start + count > bytes.length() {
    return None
  }
  let mut value = 0
  for index in start..<(start + count) {
    let ch = bytes[index].to_int()
    if ch < 48 || ch > 57 {
      return None
    }
    value = value * 10 + ch - 48
  }
  Some(value)
}

///|
fn leap(year : Int) -> Bool {
  year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

///|
fn month_days(year : Int, month : Int) -> Int {
  match month {
    1 | 3 | 5 | 7 | 8 | 10 | 12 => 31
    4 | 6 | 9 | 11 => 30
    2 => if leap(year) { 29 } else { 28 }
    _ => 0
  }
}

///|
/// Strict UTC timestamps are lexicographically ordered once validated. An
/// invalid clock value is not allowed to weaken expiration checks.
pub fn valid_utc_time(text : String) -> Bool {
  let bytes = @utf8.encode(text)
  if bytes.length() != 20 {
    return false
  }
  if bytes[4].to_int() != 45 ||
    bytes[7].to_int() != 45 ||
    bytes[10].to_int() != 84 ||
    bytes[13].to_int() != 58 ||
    bytes[16].to_int() != 58 ||
    bytes[19].to_int() != 90 {
    return false
  }
  let year = match ascii_digit(text, 0, 4) {
    Some(v) => v
    None => return false
  }
  let month = match ascii_digit(text, 5, 2) {
    Some(v) => v
    None => return false
  }
  let day = match ascii_digit(text, 8, 2) {
    Some(v) => v
    None => return false
  }
  let hour = match ascii_digit(text, 11, 2) {
    Some(v) => v
    None => return false
  }
  let minute = match ascii_digit(text, 14, 2) {
    Some(v) => v
    None => return false
  }
  let second = match ascii_digit(text, 17, 2) {
    Some(v) => v
    None => return false
  }
  year > 0 &&
  month >= 1 &&
  month <= 12 &&
  day >= 1 &&
  day <= month_days(year, month) &&
  hour <= 23 &&
  minute <= 59 &&
  second <= 59
}

///|
pub fn expired(expires : String, update_start : String) -> Bool {
  // An expiry exactly at the update start instant is already expired.
  expires <= update_start
}
