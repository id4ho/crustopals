use std::collections::HashMap;

pub fn parse_kv_string(kv_string: String) -> HashMap<String, String> {
  let mut key_values: HashMap<String, String> = HashMap::new();

  let mut kv_vec: Vec<Vec<String>> = kv_string
    .split("&")
    .map(|kv_str| kv_str.split("=").map(|s| s.to_string()).collect())
    .collect();

  let mut i = 0;
  while i < kv_vec.len() {
    let kv_set = kv_vec[i].clone();
    if kv_set.len() == 1 {
      // term has a literal '&'
      let removed = kv_vec.remove(i);
      let mut next_kv_set = kv_vec[i].clone();
      next_kv_set[0] = format!("{}&{}", removed[0], next_kv_set[0].to_string());
      kv_vec[i] = next_kv_set;
    } else if kv_set.len() > 2 {
      // term has one or more literal '='s
      let key = kv_set[0].to_string();
      let value = kv_set[1..].to_vec().join("=");
      kv_vec[i] = vec![key, value];
    } else {
      i += 1;
    }
  }

  for kv in kv_vec.iter() {
    key_values.insert(kv[0].to_string(), kv[1].to_string());
  }
  key_values
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_url_key_value_strings() {
    let kv_string: String = "foo=bar".to_string();
    let mut kvs: HashMap<String, String> = HashMap::new();
    kvs.insert("foo".to_string(), "bar".to_string());

    let result = parse_kv_string(kv_string);

    assert_eq!(result, kvs);

    let multi_kv_result =
      parse_kv_string("foo=bar&baz=qux&zap=zazzle".to_string());
    kvs.insert("baz".to_string(), "qux".to_string());
    kvs.insert("zap".to_string(), "zazzle".to_string());

    assert_eq!(multi_kv_result, kvs);
  }

  #[test]
  fn it_handles_cases_with_literal_equals_and_amps() {
    let kv_string: String = "f=o=o=b&ar&ba=z=qux&zap=zazzle".to_string();
    let mut kvs: HashMap<String, String> = HashMap::new();
    kvs.insert("f".to_string(), "o=o=b".to_string());
    kvs.insert("ar&ba".to_string(), "z=qux".to_string());
    kvs.insert("zap".to_string(), "zazzle".to_string());

    let result = parse_kv_string(kv_string);

    assert_eq!(result, kvs);
  }
}
