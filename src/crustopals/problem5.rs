extern crate hex;

use crustopals::*;

pub fn solve_problem5(plaintext: &str, key: &str) -> String {
  hex::encode(&tools::xor_string(plaintext, key))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn solves_problem5() {
    let plaintext = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
    let encrypted_text = solve_problem5(plaintext, "ICE");

    assert_eq!(
      encrypted_text,
      "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
  }
}
