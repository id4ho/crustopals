use crustopals::rand;
use crustopals::rand::Rng;
use crustopals::tools;
use crustopals::tools::mt_prng::MT19937;
use std::{thread, time};

// wait random number of seconds between 40-1000 and seed the generator.. wait
// another 40-1000 and return the first 32 bit output. From this seed, figure
// out what the seed was. This is a brute force question.. you'll have an idea
// of when the seed was created. And since unix timestamps are only precise to
// the second you only have a couple thousand seeds to try.
pub fn mt_32bits_from_timestamp() -> (u32, u32) {
  random_sleep();
  let seed = tools::system_time_as_u32();
  let mut prng = MT19937::from_seed(seed);
  random_sleep();
  (prng.get_32_bits(), seed)
}

pub fn crack_timestamp_seed(
  rand32bit_output: u32,
  range_secs: u32,
) -> Result<u32, String> {
  let upper = tools::system_time_as_u32();
  let lower = upper - range_secs;
  for i in lower..=upper {
    let mut test_prng = MT19937::from_seed(i);
    if rand32bit_output == test_prng.get_32_bits() {
      return Ok(i);
    }
  }
  Err("Didn't find the seed :(".to_string())
}

fn random_sleep() {
  let mut rng = rand::thread_rng();
  let seconds = rng.gen_range(40, 1000);
  thread::sleep(time::Duration::from_secs(seconds));
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_cracks_mt_seeded_with_unix_timestamp() {
    let (rand_output, seed_used): (u32, u32) = mt_32bits_from_timestamp();
    let cracked_seed = crack_timestamp_seed(rand_output, 2000).unwrap();

    assert_eq!(seed_used, cracked_seed);
  }
}
