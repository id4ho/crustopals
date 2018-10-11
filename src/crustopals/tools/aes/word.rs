use super::*;
use std::fmt;
use std::ops::Index;

#[derive(Clone)]
pub struct Word {
  pub bytes: [u8; 4],
}

impl Word {
  pub fn new(slice: &[u8]) -> Word {
    let mut bytes: [u8; 4] = Default::default();
    bytes.copy_from_slice(slice);
    Word { bytes }
  }

  pub fn xor(&self, other: &Word) -> Word {
    Word::new(&tools::xor_bytes(&self.bytes, &other.bytes)[..])
  }

  pub fn rotated(&self) -> Word {
    Word::new(&[self.bytes[1], self.bytes[2], self.bytes[3], self.bytes[0]])
  }

  pub fn sbox_mapped(&self) -> Word {
    Word::new(&[
      s_box(self.bytes[0]),
      s_box(self.bytes[1]),
      s_box(self.bytes[2]),
      s_box(self.bytes[3]),
    ])
  }

  pub fn inv_sbox_mapped(&self) -> Word {
    Word::new(&[
      inv_s_box(self.bytes[0]),
      inv_s_box(self.bytes[1]),
      inv_s_box(self.bytes[2]),
      inv_s_box(self.bytes[3]),
    ])
  }
}

impl PartialEq for Word {
  fn eq(&self, other: &Word) -> bool {
    self.bytes == other.bytes
  }
}

impl fmt::Debug for Word {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let mut iter = self.bytes.iter();
    write!(
      f,
      "{:02x}{:02x}{:02x}{:02x}",
      iter.next().unwrap(),
      iter.next().unwrap(),
      iter.next().unwrap(),
      iter.next().unwrap(),
    )
  }
}

impl Index<usize> for Word {
  type Output = u8;

  fn index(&self, index: usize) -> &u8 {
    &self.bytes[index]
  }
}
