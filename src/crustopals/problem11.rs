extern crate rand;

use self::rand::Rng;
use crustopals::problem8;
use crustopals::tools::*;

pub fn aes_ecb_cbc_oracle(ciphertext: &[u8]) -> String {
  if problem8::has_repeat_blocks(ciphertext) {
    "ecb".to_string()
  } else {
    "cbc".to_string()
  }
}

pub fn random_aes_encryption(message: String) -> (String, Vec<u8>) {
  let msg_bytes: Vec<u8> = append_prepend(message);
  let random_key = aes::generate_key();

  if rand::random() {
    println!("doing ecb");
    (
      String::from("ecb"),
      aes::encrypt_message_ecb(&msg_bytes, &random_key),
    )
  } else {
    let random_iv = aes::generate_iv();
    (
      String::from("cbc"),
      aes::encrypt_message_cbc(&msg_bytes, &random_key, &random_iv),
    )
  }
}

fn append_prepend(body: String) -> Vec<u8> {
  let mut rng = rand::thread_rng();
  let prepend_num = rng.gen_range(5, 10);
  let append_num = rng.gen_range(5, 10);
  let mut message = aes::generate_rand_bytes(prepend_num);
  message.extend(body.as_bytes().to_vec());
  message.extend(aes::generate_rand_bytes(append_num));
  message
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_can_detect_cbc_or_ecb() {
    let msg = "this is a message with some large part repeated.  with some \
large part repeated. The repeated portion is gt 32 bytes which means that \
regardless of where the block demarcations happen, there will be a repeated 16 \
bytes block in the ciphertext (when using ecb)".to_string();
    let (mode, rand_encrypted) = random_aes_encryption(msg);
    let oracle_result = aes_ecb_cbc_oracle(&rand_encrypted);

    assert_eq!(mode, oracle_result);
  }
}
