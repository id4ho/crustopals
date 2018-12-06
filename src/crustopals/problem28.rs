extern crate sha1;

use crustopals::tools::*;

pub fn generate_sha1_padding(bytes: &[u8]) -> Vec<u8> {
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

pub fn forge_mac(mac: &[u8], msg: &[u8], forged_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
  let fake_secret = [0u8; 16]; // "guess" of 16 bytes
  let mut full_msg: Vec<u8> = vec![];
  full_msg.extend(fake_secret.to_vec());
  full_msg.extend(msg.to_vec());
  let padding = generate_sha1_padding(&full_msg);

  let blks_len = (full_msg.len() as u64 / 64) * 64;
  let padding_len = padding.len() as u64;

  let mut forged_msg: Vec<u8> = vec![];
  forged_msg.extend(&full_msg[16..blks_len as usize].to_vec());
  forged_msg.extend(padding);


  let sha1_state = sha1_state_from_digest(mac);
  let length = blks_len + padding_len;
  let mut sha1 = sha1::Sha1::new_with_state_and_len(sha1_state, length);
  sha1.update(&forged_bytes);
  let forged_sha = hex::decode(sha1.hexdigest()).unwrap();

  forged_msg.extend(forged_bytes.to_vec());
  (forged_sha, forged_msg)
}

fn sha1_state_from_digest(digest_bytes: &[u8]) -> sha1::Sha1State {
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
  use crustopals::query_string;

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

    assert_eq!(generate_sha1_padding(quote1.as_bytes()), padding1);
    assert_eq!(generate_sha1_padding(quote2.as_bytes()), padding2);
  }

  #[test]
  fn it_can_forge_a_valid_mac() {
    let secret_key: Vec<u8> = aes::generate_key(); //random 16 byte key
    let msg_bytes = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".as_bytes();
    let legit_mac = authentication::sha1_mac(&secret_key, &msg_bytes);
    let desired_append_bytes = ";admin=true;".as_bytes();

    let (forged_mac, forged_msg) =
      forge_mac(&legit_mac, &msg_bytes, &desired_append_bytes); 

    assert!(query_string::has_admin_rights(&forged_msg));
    assert!(
      authentication::valid_sha1_mac(&secret_key, &forged_msg, forged_mac)
    );
  }
}
