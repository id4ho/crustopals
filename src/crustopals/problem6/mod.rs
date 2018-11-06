extern crate hex;

use crustopals::problem3::*;
use crustopals::tools::*;
use crustopals::*;
use std::cmp;
use std::cmp::Ordering;
use std::collections::HashMap;

pub fn break_vigeneres(bytes: &Vec<u8>) -> String {
  let most_likely_keysizes = most_likely_keysizes(bytes);
  let mut possible_solutions: Vec<(f32, String)> = vec![];

  for keysize in most_likely_keysizes {
    let (english_distance, possible_pt) =
      possible_solution_for_keysize(&bytes, keysize);
    possible_solutions.push((english_distance, possible_pt));
  }

  possible_solutions
    .into_iter()
    .min_by(|(d1, _), (d2, _)| d1.partial_cmp(d2).unwrap_or(Ordering::Equal))
    .unwrap()
    .1
}

pub fn possible_solution_for_keysize(
  bytes: &Vec<u8>,
  keysize: u32,
) -> (f32, String) {
  let key = find_likely_key(&bytes, keysize);
  let expanded_key = tools::expand_bytes(&key, bytes.len());
  let plaintext_bytes = xor_bytes(bytes, &expanded_key);
  let possible_pt = tools::bytes_to_string(plaintext_bytes);
  let english_distance = freq_analysis::english_distance(&possible_pt);
  (english_distance, possible_pt)
}

fn find_likely_key(bytes: &[u8], keysize: u32) -> Vec<u8> {
  let transposed_blocks = transpose_blocks(bytes, keysize);
  let mut possible_hex_key = String::new();
  for j in 0..keysize {
    let (_, _, hex_key): (f32, String, String) =
      solve_single_byte_xor(transposed_blocks.get(&j).unwrap());
    possible_hex_key.push_str(&hex_key);
  }
  hex::decode(possible_hex_key).unwrap()
}

fn transpose_blocks(bytes: &[u8], keysize: u32) -> HashMap<u32, String> {
  let mut transposed_blocks = HashMap::new();
  for (i, byte) in bytes.iter().enumerate() {
    transposed_blocks
      .entry(i as u32 % keysize)
      .or_insert(format!("{:02x}", byte))
      .push_str(&format!("{:02x}", byte));
  }
  transposed_blocks
}

fn most_likely_keysizes(bytes: &Vec<u8>) -> Vec<u32> {
  score_keysizes(&bytes)[0..3]
    .to_vec()
    .into_iter()
    .map(|(_, keysize)| keysize)
    .collect()
}

fn score_keysizes(bytes: &Vec<u8>) -> Vec<(f32, u32)> {
  let mut keysizes_and_scores: Vec<(f32, u32)> = (2..40)
    .map(|keysize| (h_dist_for_keysize(bytes, keysize as usize), keysize))
    .collect();

  keysizes_and_scores.sort_by(|(score1, _), (score2, _)| {
    score1.partial_cmp(score2).unwrap_or(Ordering::Equal)
  });

  keysizes_and_scores
}

// fn max_block_size(bytes: &vec<u8>) -> u32 {
//   cmp::min(40, bytes.len() / 2)
// }

fn h_dist_for_keysize(bytes: &Vec<u8>, keysize: usize) -> f32 {
  let num_blocks: u32 = cmp::min(4, (bytes.len() / keysize) as u32);
  let mut blocks: Vec<&[u8]> = vec![];
  for i in 0..num_blocks {
    let start = i as usize * keysize;
    let end = (i + 1) as usize * keysize;
    blocks.push(&bytes[start..end]);
  }
  let mut normalized_h_distances = 0.0;
  let mut comparisons = 0;
  for (i, block1) in blocks.to_vec().iter().enumerate() {
    for (j, block2) in blocks.to_vec().iter().enumerate() {
      if j > i {
        let hamming_distance = tools::hamming_distance(block1, block2);
        normalized_h_distances += hamming_distance as f32 / keysize as f32;
        comparisons += 1;
      }
    }
  }
  normalized_h_distances / comparisons as f32
}

#[cfg(test)]
mod tests {
  extern crate base64;

  use super::*;
  use std::fs;
  use std::fs::File;
  use std::io::{BufRead, BufReader};

  fn ciphertext_bytes() -> Vec<u8> {
    let mut ciphertext_base64 = String::new();
    let base64_file = File::open("src/crustopals/problem6/6.txt").unwrap();
    let reader = BufReader::new(base64_file);
    for line in reader.lines() {
      ciphertext_base64.push_str(&line.unwrap())
    }
    base64::decode(&ciphertext_base64).unwrap()
  }

  #[test]
  fn breaks_vigeneres_cipher() {
    let solution =
      fs::read_to_string("src/crustopals/problem6/solution.txt").unwrap();
    let plaintext = break_vigeneres(&ciphertext_bytes());

    assert_eq!(plaintext, solution);
  }
}
