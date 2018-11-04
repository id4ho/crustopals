extern crate base64;

use crustopals::rand::{thread_rng, Rng};
use crustopals::tools::*;

lazy_static! {
  pub static ref RANDOM_KEY: Vec<u8> = aes::generate_key();
  pub static ref IV: Vec<u8> = aes::generate_iv();
}

pub fn cbc_encrypt() -> Vec<u8> {
  let messages: Vec<&str> = vec![
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
  ];
  let mut rng = thread_rng();
  let b64_msg = rng.choose(&messages).unwrap();
  let msg = base64::decode(b64_msg.clone()).unwrap();
  aes::encrypt_message_cbc(&msg, &RANDOM_KEY.to_vec(), &IV.to_vec())
}

pub fn prob17_cbc_decrypt(iv_and_ct: &[u8]) -> bool {
  let iv = &iv_and_ct[0..16];
  let ct = &iv_and_ct[16..];
  match aes::decrypt_message_cbc(ct, &RANDOM_KEY.to_vec(), iv) {
    Ok(_) => true,
    Err(_) => false,
  }
}

pub fn crack_cbc_using_padding_oracle() -> Vec<u8> {
  // You can xor the last byte in the second to last ct block with a random
  // character.. if it comes out valid.. you know that the actual plaintext xor
  // the character you used is \x01.
  // You can then use this information to coerce the last plaintext charcter to
  // \x02 and try for the second to last character.. working backwards. Pretty
  // simple. This requires that we can supply the IV in order to get the full
  // ciphertext, otherwise we'd everything but the first block
  let ct = cbc_encrypt();
  let iv = IV.to_vec();
  let mut plaintext: Vec<u8> = vec![];
  let iv_with_ct = [&iv[..], &ct[..]].concat();
  let num_blocks = ct.len() / 16;
  for ct_block_idx in 0..num_blocks {
    for byte in crack_block(ct_block_idx, &iv_with_ct) {
      plaintext.push(byte);
    }
  }
  strip_pkcs7_padding(plaintext).unwrap()
}

fn crack_block(block_idx: usize, iv_with_ct: &[u8]) -> Vec<u8> {
  let mut recovered_block: Vec<u8> = vec![];
  // here 0 yeilds IV..which is manipulated to recover block 0 of the CT
  let blk_start = block_idx * 16;
  let blk_end = blk_start + 16;
  let pre_target_ct: Vec<u8> = iv_with_ct[0..blk_start].to_vec();
  let manipulated_blk = iv_with_ct[blk_start..blk_end].to_vec();
  let target_blk = iv_with_ct[blk_end..(blk_end + 16)].to_vec();

  while recovered_block.len() < 16 {
    let target_byte_idx = 16 - recovered_block.len() - 1;
    let target_byte = manipulated_blk[target_byte_idx];
    let pre_target_ct =
      [&pre_target_ct[..], &manipulated_blk[0..target_byte_idx]].concat();
    let pad_byte = (recovered_block.len() + 1) as u8;
    let post_target_padding_bytes = gen_valid_padding(
      &manipulated_blk[(target_byte_idx + 1)..],
      &recovered_block,
      pad_byte,
    );
    match recover_byte(
      &pre_target_ct,
      &target_byte,
      &post_target_padding_bytes,
      &target_blk,
    ) {
      Ok(byte_that_xors_pt_to_correct_padding) => {
        let recovered_byte = byte_that_xors_pt_to_correct_padding ^ pad_byte;
        // need to shift this byte onto the front of the array.. :(
        recovered_block =
          [&vec![recovered_byte][..], &recovered_block[..]].concat();
      }
      Err(error) => panic!(error),
    };
  }
  recovered_block
}

fn recover_byte(
  start_ct: &[u8],
  target_byte: &u8,
  padding_ct: &[u8],
  target_blk: &[u8],
) -> Result<u8, String> {
  for byte in (0u8..=255).rev() {
    let test_byte = target_byte ^ byte;
    let modified_iv_and_ct = [
      &start_ct[..],
      &vec![test_byte],
      &padding_ct[..],
      &target_blk,
    ]
      .concat();
    if prob17_cbc_decrypt(&modified_iv_and_ct) {
      return Ok(byte);
    }
  }
  Err("Could not find a valid byte :(".to_string())
}

fn gen_valid_padding(
  prev_blk_ct_bytes: &[u8],
  pt_bytes: &[u8],
  desired_pad: u8,
) -> Vec<u8> {
  // XOR the CT of block_n-1 with the PT of block_n and the padding bytes and
  // you'd get the decryption oracle to decrypt to the padding string that
  // padding string will be the outcome. (since you've xored )
  let padding_vec = build_byte_vec(desired_pad, (desired_pad - 1) as usize);
  let tmp_xor = xor_bytes(prev_blk_ct_bytes, pt_bytes);
  xor_bytes(&tmp_xor, &padding_vec)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_can_decrypt_using_the_padding_oracle() {
    let possible_results = [
      "000000Now that the party is jumping".to_string(),
      "000001With the bass kicked in and the Vega's are pumpin'".to_string(),
      "000002Quick to the point, to the point, no faking".to_string(),
      "000003Cooking MC's like a pound of bacon".to_string(),
      "000004Burning 'em, if you ain't quick and nimble".to_string(),
      "000005I go crazy when I hear a cymbal".to_string(),
      "000006And a high hat with a souped up tempo".to_string(),
      "000007I'm on a roll, it's time to go solo".to_string(),
      "000008ollin' in my five point oh".to_string(),
      "000009ith my rag-top down so my hair can blow".to_string(),
    ];
    let result = crack_cbc_using_padding_oracle();
    let result_str = bytes_to_string(result);
    println!("result: {:?}", result_str);

    assert!(possible_results.contains(&result_str));
  }
}
