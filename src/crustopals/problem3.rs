extern crate hex;

use crustopals::tools::*;
use crustopals::*;
use std::cmp::Ordering;

// TODO: convert to returning a result for problem 4 iteration purposes

pub fn solve_single_byte_xor(hex_str: &str) -> (f32, String) {
  let hex_results = generate_single_byte_hex_xors(hex_str);

  let mut english_results: Vec<String> = vec![];
  for hex in hex_results {
    let decoded_hex = hex::decode(hex).unwrap();
    english_results.push(String::from_utf8_lossy(&decoded_hex).to_string());
  }

  english_results
    .into_iter()
    .map(|pt| (freq_analysis::english_distance(&pt), pt))
    .min_by(|(d1, _), (d2, _)| d1.partial_cmp(d2).unwrap_or(Ordering::Equal))
    .unwrap()
}

fn generate_single_byte_hex_xors(hex_str: &str) -> Vec<String> {
  (0..256)
    .into_iter()
    .map(|byte| format!("{:x}", byte))
    .map(|hex_key| tools::xor_hex(hex_str, &hex_key))
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn solves_simple_xor() {
    let plaintext = "Hello World";
    let ciphertext = tools::xor_string(plaintext, "a");
    let ciphertext_hex = hex::encode(ciphertext);
    let deciphered_string = problem3::solve_single_byte_xor(&ciphertext_hex);
    assert_eq!(deciphered_string.1, plaintext);
  }

  #[test]
  fn solves_problem3() {
    let ciphertext =
      "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let deciphered_string = problem3::solve_single_byte_xor(&ciphertext);

    assert_eq!(deciphered_string.1, "Cooking MC's like a pound of bacon");
  }
}
