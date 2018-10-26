use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
extern crate hex;

pub fn detect_aes_ecb(filepath: String) -> String {
  let file = File::open(filepath).unwrap();
  let reader = BufReader::new(file);
  let mut aes_line: Vec<u8> = vec![];
  for l in reader.lines() {
    let line = l.unwrap();
    let bytes = hex::decode(line).unwrap();
    if has_repeat_blocks(&bytes) {
      aes_line = bytes;
    }
  }
  hex::encode(aes_line)
}

pub fn has_repeat_blocks(blob: &[u8]) -> bool {
  let num_blocks = blob.len() / 16;
  let mut deduped_blocks = HashSet::new();

  for block in blob.chunks(16) {
    deduped_blocks.insert(block);
  }

  deduped_blocks.len() < num_blocks
}

#[cfg(test)]
mod tests {
  extern crate hex;

  use super::*;

  #[test]
  fn detects_aes_ecb_encryption() {
    let detected_aes_ecb_hex =
      detect_aes_ecb(String::from("src/crustopals/problem8/8.txt"));
    // 08649af70dc06f4fd5d2d69c744 is repeated 4 times in the below string
    let aes_hex_example =
      String::from("d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744\
cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdb\
c1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd5664891547\
89a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b299\
33f2c123c58386b06fba186a");

    assert_eq!(detected_aes_ecb_hex, aes_hex_example);
  }
}
