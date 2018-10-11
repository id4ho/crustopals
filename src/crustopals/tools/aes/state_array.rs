use super::*;
use std::fmt;

pub struct StateArray {
  block: Vec<Word>,
}

impl StateArray {
  pub fn new(slice: &[u8]) -> StateArray {
    let mut block: Vec<Word> = vec![];
    for word in slice.chunks(4) {
      block.push(Word::new(word));
    }
    StateArray { block }
  }

  pub fn apply_round_key(&mut self, key: &Vec<Word>) {
    self.block[0] = self.block[0].xor(&key[0]);
    self.block[1] = self.block[1].xor(&key[1]);
    self.block[2] = self.block[2].xor(&key[2]);
    self.block[3] = self.block[3].xor(&key[3]);
  }

  pub fn sbox_translate(&mut self) {
    for i in 0..4 {
      self.block[i] = self.block[i].sbox_mapped();
    }
  }

  pub fn shift_rows(&mut self) {
    self.transpose();
    for row in 1..4 {
      for _num_shifts in 0..row {
        self.block[row] = self.block[row].rotated();
      }
    }
    self.transpose();
  }

  pub fn mix_columns(&mut self) {
    let coef_matrix: [[u8; 4]; 4] =
      [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
    for row in 0..4 {
      let mut bytes: Vec<u8> = vec![];
      for coefficients in coef_matrix.iter() {
        let mut result: u8 = 0;
        for (b, coef) in self.block[row].bytes.iter().zip(coefficients.iter()) {
          result = result ^ tools::mult_bytes(b.clone(), coef.clone());
        }
        bytes.push(result);
      }
      self.block[row] = Word::new(&bytes);
    }
  }

  pub fn to_u8(&self) -> Vec<u8> {
    let mut u8vec = vec![];
    for row in self.block.iter() {
      u8vec.extend(row.bytes[..].to_vec())
    }
    u8vec
  }

  fn transpose(&mut self) {
    let row1: [u8; 4] = Default::default();
    let row2: [u8; 4] = Default::default();
    let row3: [u8; 4] = Default::default();
    let row4: [u8; 4] = Default::default();
    let mut words: [[u8; 4]; 4] = [row1, row2, row3, row4];
    for row in 0..4 {
      for col in 0..4 {
        words[row][col] = self.block[col][row]
      }
    }
    for (i, row) in words.iter().enumerate() {
      self.block[i] = Word::new(row);
    }
  }
}

impl fmt::Debug for StateArray {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(
      f,
      "{:?}\n{:?}\n{:?}\n{:?}",
      self.block[0], self.block[1], self.block[2], self.block[3],
    )
  }
}
