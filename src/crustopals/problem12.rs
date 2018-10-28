extern crate base64;

use crustopals::problem11;
use crustopals::tools::*;
use std::iter;

lazy_static! {
  pub static ref RANDOM_KEY: Vec<u8> = aes::generate_key();
  pub static ref APPEND_STR: String = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWct\
dG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyB\
qdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".to_string();
}

pub fn aes_128_ecb_rand_key_oracle(mut message: Vec<u8>) -> Vec<u8> {
  // let mut plaintext: Vec<u8> = message.as_bytes().to_vec();
  message.extend(base64::decode(&APPEND_STR.to_string()).unwrap());
  aes::encrypt_message_ecb(&message, &RANDOM_KEY.to_vec())
}

pub fn discover_blocksize() -> usize {
  let test_byte: u8 = 65;
  let ciphertext_len1 =
    aes_128_ecb_rand_key_oracle(build_byte_vec(test_byte, 1)).len();
  let mut ciphertext_len2 =
    aes_128_ecb_rand_key_oracle(build_byte_vec(test_byte, 2)).len();
  let mut repeats = 2;
  while ciphertext_len2 <= ciphertext_len1 {
    repeats = repeats + 1;
    let pt = build_byte_vec(test_byte, repeats);
    ciphertext_len2 = aes_128_ecb_rand_key_oracle(pt).len();
  }
  ciphertext_len2 - ciphertext_len1
}

pub fn test_ecb() -> bool {
  let test_bytes =
    "two blocks of message repeating two blocks of message repeating "
      .to_string()
      .as_bytes()
      .to_vec();
  let ciphertext = aes_128_ecb_rand_key_oracle(test_bytes);
  let mode: String = problem11::aes_ecb_cbc_oracle(&ciphertext);
  "ecb".to_string() == mode
}

pub fn crack_the_aes_ecb_oracle() -> Vec<u8> {
  let block_size = discover_blocksize();
  let mut recovered_pt: Vec<u8> = vec![];
  while recovered_pt.len() < 16 {
    let mut oracle_msg =
      build_byte_vec(65, block_size - 1 - recovered_pt.len());
    let ct_block = &aes_128_ecb_rand_key_oracle(oracle_msg.clone())[0..16];
    oracle_msg.extend(recovered_pt.to_vec());
    recovered_pt.push(find_next_pt_byte(oracle_msg, ct_block).unwrap());
  }
  println!("{}", bytes_to_string(recovered_pt.clone()));
  recovered_pt
}

fn find_next_pt_byte(oracle_msg: Vec<u8>, block: &[u8]) -> Result<u8, &str> {
  println!("{:?}", oracle_msg);
  for byte in 0u8..=255 {
    let mut msg = oracle_msg.clone();
    msg.push(byte);
    let ct = aes_128_ecb_rand_key_oracle(msg);
    if block == &ct[0..16] {
      return Ok(byte);
    }
  }
  Err("Failed to find byte :(")
}

fn build_byte_vec(byte: u8, size: usize) -> Vec<u8> {
  iter::repeat(byte).take(size).collect::<Vec<u8>>()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn cracks_the_oracle() {
    crack_the_aes_ecb_oracle();

    assert_eq!(2, 3);
  }

  #[test]
  fn can_determine_blocksize() {
    assert_eq!(discover_blocksize(), 16);
  }

  #[test]
  fn confirms_ecb_mode() {
    assert_eq!(test_ecb(), true);
  }
}
