extern crate hex;

use crustopals::tools::*;
use crustopals::*;
use std::cmp::Ordering;

pub fn solve_single_byte_xor(xord_str: &str) -> String {
  let result: (f32, String, String) = (0u8..128)
    .into_iter()
    .map(|u8num| (u8num as char).to_string())
    .map(|key| (tools::xor_string(xord_str, &key), key))
    .map(|(pt, key)| (freq_analysis::english_distance(&pt), pt, key))
    .min_by(|(d1, _, _), (d2, _, _)| {
      d1.partial_cmp(d2).unwrap_or(Ordering::Equal)
    }).unwrap();

  result.1
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn solves_simple_xor() {
    let plaintext = "Hello World";
    let ciphertext = tools::xor_string(plaintext, "a");
    let deciphered_string = problem3::solve_single_byte_xor(&ciphertext);

    assert_eq!(deciphered_string, plaintext);
  }

  #[test]
  fn solves_problem3() {
    let hexstring =
      "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let ciphertext: String = hex::decode(hexstring)
      .unwrap()
      .into_iter()
      .map(|b| b as char)
      .collect();
    let deciphered_string = problem3::solve_single_byte_xor(&ciphertext);

    assert_eq!(deciphered_string, "Cooking MC's like a pound of bacon");
  }
}
