use crustopals::tools::mt_prng::MT19937;

pub fn clone_prng(outputs: Vec<u32>) -> MT19937 {
  let built_up_state: Vec<u32> =
    outputs.iter().map(|out| untemper(*out)).collect();
  MT19937::from_state(built_up_state)
}

pub fn untemper(mut val: u32) -> u32 {
  val ^= val >> 18;
  val ^= val << 15 & 0xefc60000;
  val = invert_second_op(val);
  val = invert_first_op(val);
  val
}

fn invert_second_op(val: u32) -> u32 {
  let mut bit_mask = 0x7f; // low 7 bits
  let mut recovered_bits = val & bit_mask;
  while bit_mask < 0x80000000 {
    let next_slice = recovered_bits << 7;
    let and_with_magic_num = next_slice & 0x9d2c5680;
    let xord_with_input = and_with_magic_num ^ val;
    bit_mask <<= 7;
    recovered_bits |= bit_mask & xord_with_input;
  }
  recovered_bits
}

fn invert_first_op(val: u32) -> u32 {
  let mut bit_mask = 0xFFE00000; // high 11 bits
  let mut recovered_bits = val & bit_mask;
  while bit_mask & 1 != 1 {
    let next_slice = recovered_bits >> 11;
    let xord_with_input = next_slice ^ val;
    bit_mask >>= 11;
    recovered_bits |= bit_mask & xord_with_input;
  }
  recovered_bits
}

#[cfg(test)]
mod test {
  use super::*;
  use crustopals::rand;
  use crustopals::tools::mt_prng::MT19937;

  #[test]
  fn clones_the_prng() {
    let seed = rand::random::<u32>();
    let mut target_prng = MT19937::from_seed(seed);
    let mut outputs: Vec<u32> = vec![];
    for _i in 0..624 {
      outputs.push(target_prng.get_32_bits());
    }
    let mut cloned_prng = clone_prng(outputs);

    assert_eq!(target_prng.get_32_bits(), cloned_prng.get_32_bits());
    assert_eq!(target_prng.get_32_bits(), cloned_prng.get_32_bits());
    assert_eq!(target_prng.get_32_bits(), cloned_prng.get_32_bits());
    assert_eq!(target_prng.get_32_bits(), cloned_prng.get_32_bits());
    assert_eq!(target_prng.get_32_bits(), cloned_prng.get_32_bits());
  }

  #[test]
  fn inverts_tempering() {
    for _i in 0..10 {
      let initial_value: u32 = rand::random::<u32>();
      let tempered = MT19937::temper(initial_value);
      let untempered = untemper(tempered);

      assert_eq!(untempered, initial_value);
    }
  }
}
