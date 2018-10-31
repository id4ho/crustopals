extern crate base64;
extern crate rand;

use crustopals::problem12;
use crustopals::tools::*;

lazy_static! {
  pub static ref RANDOM_KEY: Vec<u8> = aes::generate_key();
  pub static ref APPEND_STR: String = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWct\
dG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyB\
qdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".to_string();
}

pub fn aes_128_ecb_rand_prepend_oracle(message: Vec<u8>) -> Vec<u8> {
  let mut plaintext = random_bytes();
  plaintext.extend(message);
  plaintext.extend(base64::decode(&APPEND_STR.to_string()).unwrap());
  aes::encrypt_message_ecb(&plaintext, &RANDOM_KEY.to_vec())
}

pub fn crack_the_oracle() -> Vec<u8> {
  let block_size = problem12::discover_blocksize();
  let mut recovered_pt: Vec<u8> = vec![];
  let queue_blocks: Vec<u8> = problem12::build_byte_vec(66, 32); // two blocks of 'B's
  let mut recovered_padding: bool = false;
  while !recovered_padding {
    if let Some(&1u8) = recovered_pt.last() {
      recovered_padding = true;
      recovered_pt.pop();
    } else {
      let padding_to_make_attack_string_1_byte_short =
        problem12::build_byte_vec(
          65,
          block_size - 1 - (recovered_pt.len() % block_size),
        );
      let mut oracle_msg: Vec<u8> = vec![];
      oracle_msg.extend(queue_blocks.to_vec());
      oracle_msg.extend(padding_to_make_attack_string_1_byte_short);
      let total_msg = [&oracle_msg[..], &recovered_pt[..]].concat();
      loop {
        let ct = aes_128_ecb_rand_prepend_oracle(oracle_msg.clone());
        match find_first_identity_blk(ct.clone()) {
          Some(blk_num) => {
            let rel_blk_num = blk_num + (total_msg.len() / block_size);
            let relevant_ct_blk =
              &ct[(rel_blk_num * block_size)..((rel_blk_num + 1) * block_size)];
            recovered_pt
              .push(find_next_pt_byte(total_msg, relevant_ct_blk).unwrap());
            println!("recovered: {:?}", bytes_to_string(recovered_pt.clone()));
            break;
          }
          None => (),
        }
      }
    }
  }
  recovered_pt
}

fn find_next_pt_byte(oracle_msg: Vec<u8>, block: &[u8]) -> Result<u8, &str> {
  for byte in 0u8..=128 {
    let mut msg = oracle_msg.clone();
    msg.push(byte);
    loop {
      let ct = aes_128_ecb_rand_prepend_oracle(msg.clone());
      match find_first_identity_blk(ct.clone()) {
        Some(blk_num) => {
          let rel_blk_num = blk_num + (oracle_msg.len() / 16);
          if block == &ct[(rel_blk_num * 16)..((rel_blk_num + 1) * 16)] {
            return Ok(byte);
          }
          break;
        }
        None => (),
      }
    }
  }
  Err("Failed to find byte :(")
}

fn find_first_identity_blk(ct: Vec<u8>) -> Option<usize> {
  let mut last_blk: Vec<u8> = vec![];
  for (i, blk) in ct.chunks(16).enumerate() {
    if last_blk == blk {
      return Some(i - 1);
    } else {
      last_blk = blk.to_vec();
    }
  }
  None
}

fn random_bytes() -> Vec<u8> {
  let num_bytes: u8 = rand::random();
  aes::generate_rand_bytes(num_bytes as usize)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn cracks_the_random_prepend_oracle() {
    let recovered_pt_bytes = crack_the_oracle();
    let recovered_pt = bytes_to_string(recovered_pt_bytes);

    assert_eq!(recovered_pt, "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n");
  }
}
