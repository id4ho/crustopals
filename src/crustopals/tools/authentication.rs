extern crate sha1;

pub fn sha1_mac(key: &[u8], message_bytes: &[u8]) -> Vec<u8> {
  // let mut key_and_msg = Vec<u8>;
  // key_and_msg.push_str(key);
  // key_and_msg.push_str(message);
  let mut sha1 = sha1::Sha1::new();
  sha1.update(&key[..]);
  sha1.update(&message_bytes[..]);
  hex::decode(sha1.hexdigest()).unwrap()
  // sha1::Sha1::from(key_and_msg).digest()
}

pub fn valid_sha1_mac(key: &[u8], message: &[u8], mac: Vec<u8>) -> bool {
  sha1_mac(key, message) == mac
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_hashes_the_key_and_msg() {
    let key = "secretcode".as_bytes();
    let message = "this is the message".as_bytes();
    let hash = sha1_mac(&key, &message);
    let expected_result =
      hex::decode("e1f2efdf667f18621ade8a1d4387b9e0d2e6f332").unwrap();

    assert_eq!(hash, expected_result);
  }

  #[test]
  fn it_verifies_macs() {
    let key = "secretcode".as_bytes();
    let message = "this is the message".as_bytes();
    let hash = sha1_mac(&key, &message);

    assert!(valid_sha1_mac(&key, &message, hash));
  }

  #[test]
  fn it_will_not_verify_invalid_macs() {
    let key = "secretcode".as_bytes();
    let message = "this is the message".as_bytes();
    let hash = sha1_mac(&key, &message);

    assert!(!valid_sha1_mac(&key, "this is a forged message".as_bytes(), hash));
  }
}
