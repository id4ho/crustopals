extern crate sha1;
extern crate md4;

use self::md4::{Md4, Digest};

pub fn sha1_mac(key: &[u8], message_bytes: &[u8]) -> Vec<u8> {
  let mut sha1 = sha1::Sha1::new();
  sha1.update(&key[..]);
  sha1.update(&message_bytes[..]);
  hex::decode(sha1.hexdigest()).unwrap()
}

pub fn md4_mac(key: &[u8], message_bytes: &[u8]) -> Vec<u8> {
  let mut md4 = self::Md4::new();
  md4.input(&key[..]);
  md4.input(&message_bytes[..]);
  md4.result().to_vec()
}

pub fn valid_sha1_mac(key: &[u8], message: &[u8], mac: Vec<u8>) -> bool {
  sha1_mac(key, message) == mac
}

pub fn valid_md4_mac(key: &[u8], message: &[u8], mac: Vec<u8>) -> bool {
  md4_mac(key, message) == mac
}

#[cfg(test)]
mod tests {
  use super::*;

  ///////////////////////////////////////////////////////////////////////
  // SHA1
  ///////////////////////////////////////////////////////////////////////
  #[test]
  fn it_hashes_the_key_and_msg_sha1() {
    let key = "secretcode".as_bytes();
    let message = "this is the message".as_bytes();
    let hash = sha1_mac(&key, &message);
    let expected_result =
      hex::decode("e1f2efdf667f18621ade8a1d4387b9e0d2e6f332").unwrap();

    assert_eq!(hash, expected_result);
  }

  #[test]
  fn it_verifies_sha1_macs() {
    let key = "secretcode".as_bytes();
    let message = "this is the message".as_bytes();
    let hash = sha1_mac(&key, &message);

    assert!(valid_sha1_mac(&key, &message, hash));
  }

  #[test]
  fn it_wont_verify_invalid_sha1_macs() {
    let key = "secretcode".as_bytes();
    let message = "this is the message".as_bytes();
    let hash = sha1_mac(&key, &message);

    assert!(!valid_sha1_mac(&key, "this is a forged message".as_bytes(), hash));
  }

  ///////////////////////////////////////////////////////////////////////
  // MD4
  ///////////////////////////////////////////////////////////////////////
  #[test]
  fn it_hashes_the_key_and_msg_md4() {
    let key = "secretcode".as_bytes();
    let message = "this is the message".as_bytes();
    let hash = md4_mac(&key, &message);
    let expected_result =
      hex::decode("64c19c66b3df2304abd9126a0302a78a").unwrap();

    assert_eq!(hash, expected_result);
  }

  #[test]
  fn it_verifies_md4_macs() {
    let key = "secretcode".as_bytes();
    let message = "this is the message".as_bytes();
    let hash = md4_mac(&key, &message);

    assert!(valid_md4_mac(&key, &message, hash));
  }

  #[test]
  fn it_wont_verify_invalid_md4_macs() {
    let key = "secretcode".as_bytes();
    let message = "this is the message".as_bytes();
    let hash = md4_mac(&key, &message);

    assert!(!valid_md4_mac(&key, "this is a forged message".as_bytes(), hash));
  }
}
