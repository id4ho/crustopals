extern crate base64;

use crustopals::problem11;
use crustopals::tools::*;

lazy_static! {
  pub static ref RANDOM_KEY: Vec<u8> = aes::generate_key();
  pub static ref PREPEND_STR: String = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".to_string();
}

pub fn aes_128_ecb_rand_key_oracle(message: String) -> Vec<u8> {
  let mut plaintext: Vec<u8> =
    base64::decode(&PREPEND_STR.to_string()).unwrap();
  plaintext.extend(message.as_bytes());
  aes::encrypt_message_ecb(&plaintext, &RANDOM_KEY.to_vec())
}

pub fn discover_blocksize() -> usize {
  let test_byte = "A".to_string();
  let ciphertext_len1 = aes_128_ecb_rand_key_oracle(test_byte.repeat(1)).len();
  let mut ciphertext_len2 =
    aes_128_ecb_rand_key_oracle(test_byte.repeat(2)).len();
  let mut repeats = 2;
  while ciphertext_len2 <= ciphertext_len1 {
    repeats = repeats + 1;
    let pt = test_byte.repeat(repeats);
    ciphertext_len2 = aes_128_ecb_rand_key_oracle(pt).len();
  }
  ciphertext_len2 - ciphertext_len1
}

pub fn test_ecb() -> bool {
  let test_str =
    "two blocks of message repeating two blocks of message repeating "
      .to_string();
  let ciphertext = aes_128_ecb_rand_key_oracle(test_str);
  let mode: String = problem11::aes_ecb_cbc_oracle(&ciphertext);
  "ecb".to_string() == mode
}

pub fn determine_even_block_msg() -> String {
  let mut msg = "A".to_string();
  let mut ciphertext = aes_128_ecb_rand_key_oracle(msg.clone());
  let ciphertext_len = ciphertext.len();
  while ciphertext.len() == ciphertext_len {
    msg = format!("{}A", msg);
    ciphertext = aes_128_ecb_rand_key_oracle(msg.clone());
  }
  msg
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn finds_even_test_block() {
    let full_block = determine_even_block_msg();
    assert_eq!(full_block, "AAAAAA");
  }

  #[test]
  fn can_determine_blocksize() {
    assert_eq!(discover_blocksize(), 16);
  }

  #[test]
  fn confirms_ecb_mode() {
    assert_eq!(test_ecb(), true);
  }

  #[test]
  fn view_rand_key() {
    aes_128_ecb_rand_key_oracle("OK".to_string());

    assert_eq!(2, 3);
  }
}
