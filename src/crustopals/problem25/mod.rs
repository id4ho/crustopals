use crustopals::tools;
use crustopals::tools::aes;

lazy_static! {
  pub static ref RANDOM_KEY: Vec<u8> = aes::generate_key();
  pub static ref NONCE: Vec<u8> = aes::generate_rand_bytes(8);
}

pub fn ctr_encrypt_with_unknown_key(pt: &[u8]) -> Vec<u8> {
  aes::encrypt_ctr(&pt, &RANDOM_KEY, &NONCE)
}

pub fn recover_pt_from_ct(ct: &[u8]) -> Vec<u8> {
  let known_pt = "a".repeat(ct.len());
  let known_pt_bytes = known_pt.as_bytes();
  let mut new_ct: Vec<u8> = ct.clone().to_vec();
  edit(&mut new_ct, 0, known_pt_bytes);
  let ctr_stream = tools::xor_bytes(&known_pt_bytes, &new_ct);
  tools::xor_bytes(&ctr_stream, ct)
}

pub fn edit(ciphertext: &mut Vec<u8>, offset: usize, newtext: &[u8]) {
  let stream_length = offset + newtext.len();
  let ctr_stream = aes::generate_ctr_stream(&RANDOM_KEY, &NONCE, stream_length);
  for i in 0..newtext.len() {
    ciphertext[i + offset] = newtext[i] ^ ctr_stream[i + offset];
  }
}

#[cfg(test)]
mod tests {
  extern crate base64;

  use super::*;
  use std::fs::File;
  use std::io::{BufRead, BufReader};

  fn plaintext() -> Vec<u8> {
    let file = File::open("src/crustopals/problem25/25.txt").unwrap();
    let reader = BufReader::new(file);
    let mut pt_base64 = String::new();
    for line in reader.lines() {
      pt_base64.push_str(&line.unwrap())
    }
    let ciphertext_bytes = base64::decode(&pt_base64).unwrap();
    let key = "YELLOW SUBMARINE".as_bytes();
    aes::decrypt_message_ecb(&ciphertext_bytes, key).unwrap()
  }

  #[test]
  fn recovers_the_plaintext() {
    let plaintext_bytes = plaintext();
    let ciphertext = ctr_encrypt_with_unknown_key(&plaintext_bytes);
    let recovered_pt_bytes = recover_pt_from_ct(&ciphertext);

    let plaintext = tools::bytes_to_string(plaintext_bytes);
    let recovered_plaintext = tools::bytes_to_string(recovered_pt_bytes);

    assert_eq!(recovered_plaintext, plaintext);
  }
}
