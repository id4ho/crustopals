extern crate sha1;

pub fn generate_sha1_padding(bytes: &[u8]) -> Vec<u8> {
  let num_bytes = bytes.len();
  let extra_bytes = num_bytes % 64;
  let mut last_blocks = [0u8; 128];
  last_blocks[0..extra_bytes]
    .clone_from_slice(&bytes[(num_bytes - extra_bytes)..]);
  last_blocks[extra_bytes] = 0x80u8; // 10000000 in binary
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
    last_blocks[56..64].clone_from_slice(&extra);
    last_blocks[..64].to_vec()
  } else {
    last_blocks[120..128].clone_from_slice(&extra);
    last_blocks.to_vec()
  }
}

pub fn forge_mac(
  mac: &[u8],
  msg: &[u8],
  forged_bytes: &[u8],
) -> (Vec<u8>, Vec<u8>) {
  let fake_secret = [0u8; 16]; // "guess" of 16 bytes
  let mut full_msg: Vec<u8> = vec![];
  full_msg.extend(fake_secret.to_vec());
  full_msg.extend(msg.to_vec());
  // The below returns the last block that was run through the hashing algorithm
  // inclusive of padding. This should always be a round 64 bytes but it may be
  // 64 and it may be 128 depending if there was enough room to add the 1 bit
  // and the 8 byte length at the end (i.e. if the original message ran up
  // past 56 bytes but below 64 it would need almost an entire block of null
  // byte padding)
  let padding = generate_sha1_padding(&full_msg);
  let blks_len = (full_msg.len() as u64 / 64) * 64;
  let padding_len = padding.len() as u64;

  let mut forged_msg: Vec<u8> = vec![];
  if blks_len > 0 {
    forged_msg.extend(&full_msg[fake_secret.len()..blks_len as usize].to_vec());
    forged_msg.extend(padding);
  } else {
    forged_msg.extend(&padding[fake_secret.len()..].to_vec());
  }

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
  use crustopals::tools::*;

  #[test]
  fn it_generates_padding_matching_the_sha1_lib() {
    let quote1 = "Thunder rolled. It rolled a 6";
    let quote2 = "Real stupidity beats artificial intelligence every time.";
    let quote3 = "When a man says he does not want to speak of something he usually means he can think of nothing else.";
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
    let padding3: Vec<u8> = vec![
      121, 32, 109, 101, 97, 110, 115, 32, 104, 101, 32, 99, 97, 110, 32, 116,
      104, 105, 110, 107, 32, 111, 102, 32, 110, 111, 116, 104, 105, 110, 103,
      32, 101, 108, 115, 101, 46, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 40,
    ];

    assert_eq!(generate_sha1_padding(quote1.as_bytes()), padding1);
    assert_eq!(generate_sha1_padding(quote2.as_bytes()), padding2);
    assert_eq!(generate_sha1_padding(quote3.as_bytes()), padding3);
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
    assert!(authentication::valid_sha1_mac(
      &secret_key,
      &forged_msg,
      forged_mac
    ));
  }
}
