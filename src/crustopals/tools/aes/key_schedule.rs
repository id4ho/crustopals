use super::*;
use std::ops::Index;

#[derive(Debug)]
pub struct KeySchedule {
  round_keys: Vec<Vec<Word>>,
}

impl KeySchedule {
  pub fn new(slice: Vec<Word>) -> KeySchedule {
    let mut round_keys: Vec<Vec<Word>> = vec![];
    for round_key in slice.chunks(4) {
      round_keys.push(round_key.to_vec());
    }
    KeySchedule { round_keys }
  }

  pub fn round_key(&self, index: usize) -> &Vec<Word> {
    &self.round_keys[index]
  }
}

impl Index<usize> for KeySchedule {
  type Output = Word;

  fn index(&self, index: usize) -> &Word {
    &self.round_keys[index / 4][index % 4]
  }
}
