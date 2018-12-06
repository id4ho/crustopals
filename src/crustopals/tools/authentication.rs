extern crate sha1;

pub fn sha1_mac(key: &str, message: &str) -> String {
  let mut key_and_msg = String::new();
  key_and_msg.push_str(key);
  key_and_msg.push_str(message);
  sha1::Sha1::from(key_and_msg).hexdigest()
}

pub fn valid_sha1_mac(key: &str, message: &str, mac: &str) -> bool {
  &sha1_mac(key, message) == mac
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_hashes_the_key_and_msg() {
    let key = "secretcode".to_string();
    let message = "this is the message".to_string();
    let hash = sha1_mac(&key, &message);

    assert_eq!(&hash, "e1f2efdf667f18621ade8a1d4387b9e0d2e6f332");
  }

  #[test]
  fn it_verifies_macs() {
    let key = "secretcode".to_string();
    let message = "this is the message".to_string();
    let hash = sha1_mac(&key, &message);

    assert!(valid_sha1_mac(&key, &message, &hash));
  }

  #[test]
  fn it_will_not_verify_invalid_macs() {
    let key = "secretcode".to_string();
    let message = "this is the message".to_string();
    let hash = sha1_mac(&key, &message);

    assert!(!valid_sha1_mac(&key, "this is a forged message", &hash));
  }
}
