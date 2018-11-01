#[cfg(test)]
mod tests {
  extern crate base64;

  use crustopals::tools::*;
  use std::fs;
  use std::fs::File;
  use std::io::{BufRead, BufReader};

  fn ciphertext_bytes() -> Vec<u8> {
    let mut ciphertext_base64 = String::new();
    let base64_file = File::open("src/crustopals/problem7/7.txt").unwrap();
    let reader = BufReader::new(base64_file);
    for line in reader.lines() {
      ciphertext_base64.push_str(&line.unwrap())
    }
    base64::decode(&ciphertext_base64).unwrap()
  }

  #[test]
  fn solve_problem_7() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let aes_128_bit_decrypted =
      aes::decrypt_message_ecb(&ciphertext_bytes(), key).unwrap();

    assert_eq!(
      bytes_to_string(aes_128_bit_decrypted),
      fs::read_to_string("src/crustopals/problem6/solution.txt").unwrap() // same solution as 6
    );
  }
}
