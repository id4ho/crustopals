extern crate sha1;

use crustopals::tools::*;

pub fn generate_sha1_padding(msg: &str) -> Vec<u8> {
  let bytes = msg.as_bytes();
  let num_bytes = bytes.len();
  let extra_bytes = num_bytes % 64;
  let mut last_blocks = [0u8; 128]; 
  last_blocks[0..extra_bytes].clone_from_slice(&bytes[(num_bytes - extra_bytes)..]);
  // block size is 64 bytes
  // must append 8 byte length (in bits) to end of message
  // must append 1 bit + 0 pad up to the 8 byte length
  // 0x80 -> 10000000 -> 8 * 16 or 128
  // msg = "asdf"
  // actual-encryption -> [a,s,d,f,0x80u8,0u8,...,0u8,32 as u64]
  last_blocks[extra_bytes] = 0x80u8;
  let num_bits: u64 = num_bytes as u64 * 8;
  let extra = [
    (num_bits >> 56) as u8,
    (num_bits >> 48) as u8,
    (num_bits >> 40) as u8,
    (num_bits >> 32) as u8,
    (num_bits >> 24) as u8,
    (num_bits >> 16) as u8,
    (num_bits >> 8) as u8,
    num_bits as u8,
  ];
  if extra_bytes < 56 {
    // here we can pad, add the 1 bit, and 8 bytes for the length
    // without going over 64 bytes.
    last_blocks[56..64].clone_from_slice(&extra);
    last_blocks[..64].to_vec()
  } else {
    last_blocks[120..128].clone_from_slice(&extra);
    last_blocks.to_vec()
  }
}

pub fn forge_mac(mac: &str, msg: &str, forged_msg: &str) -> (String, String) {
  let fake_secret = "0".repeat(16); // "guess" of 16 bytes
  let mut full_msg = String::new();
  full_msg.push_str(&fake_secret);
  full_msg.push_str(msg);
  println!("full_msg {:?}", full_msg);
  let padding = generate_sha1_padding(&full_msg);

  let blks_len: u64 = (full_msg.as_bytes().len() as u64 / 64) * 64;
  let padding_len: u64 = padding.len() as u64;
  let len: u64 = blks_len + padding_len; 

  let forged_bytes = forged_msg.as_bytes().to_vec();
  let mut sha1 = sha1::Sha1::new_with_state_and_len(sha1_state_from_digest(mac), len);
  sha1.update(&forged_bytes);
  let forged_sha = sha1.hexdigest();

  let mut msg_with_padding = msg.to_string();
  msg_with_padding.push_str(&bytes_to_string(padding));
  println!("msg_with_padding {:?}", msg_with_padding);
  println!("msg_with_padding.len() {}", msg_with_padding.len());
  (forged_sha, msg_with_padding)
}

fn sha1_state_from_digest(digest: &str) -> sha1::Sha1State {
  let digest_bytes: Vec<u8> = hex::decode(digest).unwrap();
  let mut state = [0u32; 5];
  for i in 0..5 {
    let off = i * 4;
    state[i] = (digest_bytes[off + 3] as u32)
      | ((digest_bytes[off + 2] as u32) << 8)
      | ((digest_bytes[off + 1] as u32) << 16)
      | ((digest_bytes[off] as u32) << 24);
  }
  sha1::Sha1State { state }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_generates_padding_matching_the_sha1_lib() {
    let quote1 = "Thunder rolled. It rolled a 6";
    let quote2 = "Real stupidity beats artificial intelligence every time.";
    let padding1: Vec<u8> = vec![
      84, 104, 117, 110, 100, 101, 114, 32, 114, 111, 108, 108, 101, 100, 46,
      32, 73, 116, 32, 114, 111, 108, 108, 101, 100, 32, 97, 32, 54, 128, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 232,
    ];
    let padding2: Vec<u8> = vec![
      82, 101, 97, 108, 32, 115, 116, 117, 112, 105, 100, 105, 116, 121, 32,
      98, 101, 97, 116, 115, 32, 97, 114, 116, 105, 102, 105, 99, 105, 97, 108,
      32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99, 101, 32, 101,
      118, 101, 114, 121, 32, 116, 105, 109, 101, 46, 128, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 192,
    ];

    assert_eq!(generate_sha1_padding(quote1), padding1);
    assert_eq!(generate_sha1_padding(quote2), padding2);
  }

  #[test]
  fn it_can_forge_a_valid_mac() {
    let secret_bytes: Vec<u8> = aes::generate_key(); //random 16 byte key
    let key = bytes_to_string(secret_bytes);
    let msg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".to_string();
    let legit_mac = authentication::sha1_mac(&key, &msg);
    let desired_append = ";admin=true";

    let (forged_mac, mut forged_msg) =
      forge_mac(&legit_mac, &msg, desired_append); 

    forged_msg.push_str(desired_append);
    assert_ne!(forged_mac, legit_mac);
    // need to add glue padding between original message and forged bits
    assert!(authentication::valid_sha1_mac(&key, &forged_msg, &forged_mac));
  }
}
