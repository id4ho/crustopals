extern crate reqwest;
extern crate sha1;

use crustopals::tools;
use std::iter;
use std::{thread, time};

lazy_static! {
  pub static ref RANDOM_KEY: Vec<u8> = tools::aes::generate_key();
}

pub mod hmac_server;

pub fn hmac_sha1(key_bytes: &[u8], msg: &str) -> Vec<u8> {
  let key: Vec<u8>;
  if key_bytes.len() > 64 {
    key = sha1_hash(&key_bytes);
  } else {
    key = key_bytes.to_vec();
  }
  let mut block_sized_key = [0; 64];
  block_sized_key[0..key.len()].clone_from_slice(&key[..]);

  let outer_xor: Vec<u8> = iter::repeat(0x5c as u8).take(64).collect();
  let inner_xor: Vec<u8> = iter::repeat(0x36 as u8).take(64).collect();
  let o_key_pad = tools::xor_bytes(&block_sized_key, &outer_xor);
  let i_key_pad = tools::xor_bytes(&block_sized_key, &inner_xor);

  // HMAC hashing
  let inner_hash = sha1_hash(&[&i_key_pad[..], msg.as_bytes()].concat());
  sha1_hash(&[&o_key_pad[..], &inner_hash[..]].concat())
}

pub fn insecure_compare(filename: &str, signature: &str) -> bool {
  let hmac_filename = hmac_sha1(&RANDOM_KEY, filename);
  let sig_bytes = hex::decode(signature).unwrap();
  for i in 0..sig_bytes.len() {
    if hmac_filename[i] != sig_bytes[i] {
      return false;
    }
    thread::sleep(time::Duration::from_millis(6));
  }
  true
}

fn exploit_early_exit(filename: &str) -> Result<[u8; 20], reqwest::Error> {
  let mut signature = [0u8; 20];
  let client = reqwest::Client::new();
  let path_without_sig = format!(
    "http://127.0.0.1:9000/test_hmac?file={}&signature=",
    filename
  );
  for i in 0..signature.len() {
    let mut probable_byte = 0u8;
    let mut best_time = time::Duration::new(0, 0);
    for b in 0u8..=255 {
      signature[i] = b;
      let uri = format!("{}{}", path_without_sig, hex::encode(&signature));
      let now = time::Instant::now();
      // could try repeating this request multiple times to get an average
      let resp = client.get(&uri).send()?;
      if resp.status().is_success() {
        return Ok(signature);
      }
      let time_elapsed = now.elapsed();
      if time_elapsed > best_time {
        best_time = time_elapsed;
        probable_byte = b;
      }
    }
    signature[i] = probable_byte;
  }
  Ok(signature)
}

fn sha1_hash(bytes: &[u8]) -> Vec<u8> {
  let mut sha1 = sha1::Sha1::new();
  sha1.update(&bytes[..]);
  sha1.digest().bytes().to_vec()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_generates_an_hmac() {
    let empty_ex = hmac_sha1("".as_bytes(), "");
    let quick_brown_fox_ex = hmac_sha1(
      "key".as_bytes(),
      "The quick brown fox jumps over the lazy dog",
    );

    assert_eq!(
      empty_ex,
      hex::decode("fbdb1d1b18aa6c08324b7d64b71fb76370690e1d").unwrap()
    );
    assert_eq!(
      quick_brown_fox_ex,
      hex::decode("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9").unwrap()
    );
  }

  #[test]
  fn it_can_exploit_an_early_exit_compare() {
    thread::spawn(move || {
      hmac_server::run();
    });
    let desired_file = "/etc/passwd";
    let exploited_signature =
      exploit_early_exit(desired_file).unwrap().to_vec();
    let valid_signature = hmac_sha1(&RANDOM_KEY, desired_file);

    assert_eq!(exploited_signature, valid_signature);
  }
}
