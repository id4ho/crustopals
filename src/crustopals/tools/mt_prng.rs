use std::u32;

const N: usize = 624;
const M: usize = 397;
const F: u32 = 1812433253;
const MATRIX_A: u32 = 0x9908b0df;

pub struct MT19937 {
  seed: u32,
  state: [u32; N],
  mt_iter: u32,
}

impl MT19937 {
  pub fn from_seed(seed: u32) -> MT19937 {
    let mut prng = MT19937 {
      seed,
      state: [0u32; N],
      mt_iter: (N + 1) as u32,
    };
    prng.initialize();
    prng
  }

  fn initialize(&mut self) {
    self.state[0] = self.seed;
    for i in 1..N {
      let prev_state = self.state[i - 1];
      let prev_shifted_30 = prev_state >> 30;
      let prev_xor_prev_shifted = prev_state ^ prev_shifted_30;
      self.state[i] =
        F.wrapping_mul(prev_xor_prev_shifted).wrapping_add(i as u32);
    }
  }

  pub fn get_32_bits(&mut self) -> u32 {
    if self.mt_iter >= N as u32 {
      self.twist();
    }

    let mut result = self.state[self.mt_iter as usize];
    self.mt_iter += 1;

    // Tempering
    result ^= result >> 11;
    result ^= result << 7 & 0x9d2c5680;
    result ^= result << 15 & 0xefc60000;
    result ^= result >> 18;

    result
  }

  fn twist(&mut self) {
    let upper_mask: u32 = 1 << 31;
    let lower_mask: u32 = u32::MAX >> 1;

    for kk in 0..N {
      let next_index = (kk + 1) % N;
      let y =
        (self.state[kk] & upper_mask) | (self.state[next_index] & lower_mask);
      if kk < (N - M) {
        self.state[kk] = self.state[kk + M] ^ (y >> 1) ^ (MATRIX_A * (y & 1));
      } else if kk < (N - 1) {
        self.state[kk] =
          self.state[kk - (N - M)] ^ (y >> 1) ^ (MATRIX_A * (y & 1));
      } else {
        self.state[kk] = self.state[M - 1] ^ (y >> 1) ^ (MATRIX_A * (y & 1));
      }
    }

    self.mt_iter = 0;
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_returns_32_bits_according_to_spec() {
    let seed: u32 = 5489;
    let mut mt: MT19937 = MT19937::from_seed(seed);

    // The below numbers taken from the author's C implementation output
    // http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/emt19937ar.html
    // Note that the output provided is from the vector init, not the default
    // seed init. You must compile/run the C program to get the below output.
    assert_eq!(mt.get_32_bits(), 3499211612 as u32);
    assert_eq!(mt.get_32_bits(), 581869302 as u32);
    assert_eq!(mt.get_32_bits(), 3890346734 as u32);
    assert_eq!(mt.get_32_bits(), 3586334585 as u32);
    assert_eq!(mt.get_32_bits(), 545404204 as u32);
  }

  #[test]
  fn returns_same_sequence_for_same_seed() {
    let seed = 297456 as u32;
    let mut sequence_one = MT19937::from_seed(seed);
    let mut sequence_two = MT19937::from_seed(seed);

    assert_eq!(sequence_one.get_32_bits(), sequence_two.get_32_bits());
    assert_eq!(sequence_one.get_32_bits(), sequence_two.get_32_bits());
    assert_eq!(sequence_one.get_32_bits(), sequence_two.get_32_bits());
  }
}
