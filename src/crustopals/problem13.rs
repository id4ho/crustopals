use crustopals::tools::*;
use std::collections::HashMap;

lazy_static! {
  pub static ref RANDOM_KEY: Vec<u8> = aes::generate_key();
}

#[derive(Debug)]
pub struct Profile {
  email: String,
  role: String,
  uid: i32,
}

impl Profile {
  pub fn profile_for(email: String) -> Profile {
    Profile {
      email: email,
      uid: 10, // hardcoded
      role: "user".to_string(),
    }
  }

  pub fn from_query_string(query_str: String) -> Result<Profile, String> {
    let parsed_query_string = parse_kv_string(query_str);
    if parsed_query_string.contains_key("email")
      && parsed_query_string.contains_key("uid")
    {
      Ok(Profile {
        email: parsed_query_string.get("email").unwrap().to_string(),
        uid: parsed_query_string
          .get("uid")
          .unwrap()
          .parse::<i32>()
          .unwrap(),
        role: parsed_query_string
          .get("role")
          .unwrap_or(&"user".to_string())
          .to_string(),
      })
    } else {
      Err("Doesn't have the correct params".to_string())
    }
  }

  pub fn as_query_string(&self) -> String {
    format!("email={}&uid={}&role={}", self.email, self.uid, self.role)
  }

  pub fn encrypt(&self) -> Vec<u8> {
    aes::encrypt_message_ecb(
      &self.as_query_string().as_bytes(),
      &RANDOM_KEY.to_vec(),
    )
  }

  pub fn from_encrypted_blob(encrypted_qs: Vec<u8>) -> Result<Profile, String> {
    let decrypted_qs =
      aes::decrypt_message_ecb(&encrypted_qs, &RANDOM_KEY.to_vec());
    Profile::from_query_string(bytes_to_string(decrypted_qs))
  }
}

impl PartialEq for Profile {
  fn eq(&self, other: &Profile) -> bool {
    self.email == other.email
      && self.uid == other.uid
      && self.role == other.role
  }
}

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

  #[test]
  fn formats_a_profile_as_a_query_string() {
    let profile = Profile {
      email: "jack@email.email".to_string(),
      role: "user".to_string(),
      uid: 10,
    };
    let query_str = "email=jack@email.email&uid=10&role=user".to_string();

    let result = profile.as_query_string();

    assert_eq!(result, query_str);
  }

  #[test]
  fn generates_a_profile_from_a_query_str() {
    let query_str = "email=jack@email.email&uid=10&role=user".to_string();
    let profile = Profile {
      email: "jack@email.email".to_string(),
      role: "user".to_string(),
      uid: 10,
    };

    let result = Profile::from_query_string(query_str);

    assert_eq!(result.unwrap(), profile);
  }

  #[test]
  fn generates_a_user_profile_from_an_email() {
    let email = "jack@gmail.com".to_string();
    let result = Profile::profile_for(email.to_string());
    let profile = Profile {
      email: email,
      role: "user".to_string(),
      uid: 10,
    };

    assert_eq!(result, profile);
    assert_eq!(1, 2);
  }

  #[test]
  fn requires_a_valid_email() {
    let email = "jack@gmail.com".to_string();
    let result = Profile::profile_for(email.to_string());
    let profile = Profile {
      email: email,
      role: "user".to_string(),
      uid: 10,
    };

    assert_eq!(result, profile);
  }

  #[test]
  fn it_can_encrypt_and_decrypt_profiles() {
    let profile = Profile {
      email: "jack@gmail.com".to_string(),
      role: "user".to_string(),
      uid: 10,
    };

    let encrypted_blob = profile.encrypt();
    let decrypted_profile = Profile::from_encrypted_blob(encrypted_blob);

    assert_eq!(decrypted_profile.unwrap(), profile);
  }
}
