#[cfg(test)]
mod tests {
  extern crate base64;

  use crustopals::tools::*;
  use std::fs;
  use std::fs::File;
  use std::io::{BufRead, BufReader};

  fn ciphertext_bytes() -> Vec<u8> {
    let mut ciphertext_base64 = String::new();
    let base64_file = File::open("src/crustopals/problem10/10.txt").unwrap();
    let reader = BufReader::new(base64_file);
    for line in reader.lines() {
      ciphertext_base64.push_str(&line.unwrap())
    }
    base64::decode(&ciphertext_base64).unwrap()
  }

  #[test]
  fn solve_problem_10() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = [0 as u8; 16];
    let aes_decrypted = aes::decrypt_message_cbc(&ciphertext_bytes(), key, &iv);

    assert_eq!(
      bytes_to_string(aes_decrypted),
      fs::read_to_string("src/crustopals/problem6/solution.txt").unwrap() // same solution as 6
    );
  }
}
