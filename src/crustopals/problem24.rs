use crustopals::problem22;
use crustopals::tools::mt_prng::MT19937;
use crustopals::tools::*;

pub fn mt19937_encrypt(key: u16, message: &[u8]) -> Vec<u8> {
  xor_with_keystream(key, message)
}

pub fn mt19937_decrypt(key: u16, ciphertext: &[u8]) -> Vec<u8> {
  xor_with_keystream(key, ciphertext)
}

fn xor_with_keystream(key: u16, bytes: &[u8]) -> Vec<u8> {
  let key_stream = mt19937_stream(key as u32, bytes.len());
  xor_bytes(&bytes, &key_stream)
}

pub fn generate_password_reset_token(use_prng: bool) -> Vec<u8> {
  let token_length = 16;
  if use_prng {
    let seed = system_time_as_u32();
    return mt19937_stream(seed, token_length);
  } else {
    return aes::generate_rand_bytes(token_length);
  }
}

fn mt19937_stream(seed: u32, length: usize) -> Vec<u8> {
  let mut prng = MT19937::from_seed(seed as u32);
  let mut key_stream: Vec<u8> = vec![];

  while key_stream.len() < length {
    let bytes = word_to_bytes(prng.get_32_bits());
    key_stream.extend(bytes[..].to_vec());
  }
  key_stream[0..length].to_vec()
}

pub fn crack_prng_stream_key(ciphertext: &[u8], known_plaintext: &[u8]) -> u16 {
  let length = ciphertext.len();
  for test_seed in 0u16..=65535 {
    let stream = mt19937_stream(test_seed as u32, length);
    let proposed_pt = xor_bytes(&stream, ciphertext);
    if &proposed_pt[(length - 14)..] == known_plaintext {
      return test_seed;
    }
  }
  panic!("could not find the seed :(");
}

pub fn determine_if_token_is_prng_based(token: Vec<u8>) -> bool {
  let first_4_prng_bytes = &token[0..4];
  let prng_32_bit_output = bytes_to_word(first_4_prng_bytes);
  match problem22::crack_timestamp_seed(prng_32_bit_output, 10) {
    Ok(_) => return true,
    Err(_) => return false,
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use crustopals::rand;
  use crustopals::tools::aes::generate_rand_bytes;

  #[test]
  fn it_generates_a_specific_length_stream() {
    let seed = rand::random::<u16>();
    let length = 12; // 12 * 8 = 96 (or 3 u32s)
    let mut prng = MT19937::from_seed(seed as u32);
    let mut prng_output_to_bytes: Vec<u8> = vec![];
    for _i in 0..3 {
      let bytes = word_to_bytes(prng.get_32_bits());
      prng_output_to_bytes.extend(bytes[..].to_vec());
    }

    let stream = mt19937_stream(seed as u32, length);

    assert_eq!(stream, prng_output_to_bytes);
  }

  #[test]
  fn it_can_encrypt_and_decrypt_using_mt19937() {
    let plaintext = "here is my secret message".to_string();
    let pt_bytes = plaintext.as_bytes();
    let key = rand::random::<u16>();
    let encrypted = mt19937_encrypt(key, pt_bytes);

    assert_ne!(encrypted, pt_bytes);

    let decrypted = mt19937_decrypt(key, &encrypted);

    assert_eq!(decrypted, pt_bytes);
  }

  // Use your encrypt function to encrypt a known plaintext (say, 14 consecutive
  // 'A' characters) prefixed by a random number of random characters. From the
  // ciphertext, recover the "key" (the 16 bit seed).
  #[test]
  fn can_recover_16_bit_key_24part1() {
    let known_plaintext = "A".repeat(14);
    let known_pt_bytes = known_plaintext.as_bytes();
    let unknown_pt = generate_rand_bytes(rand::random::<u8>() as usize);
    let plaintext = [&unknown_pt[..], &known_pt_bytes[..]].concat();
    let key = rand::random::<u16>();
    let ciphertext = mt19937_encrypt(key, &plaintext);

    let recovered_key = crack_prng_stream_key(&ciphertext, &known_pt_bytes);

    assert_eq!(key, recovered_key);
  }

  #[test]
  fn can_determine_if_password_reset_key_is_prng_based_24part2() {
    for _i in 0..10 {
      let prng_based = rand::random();
      let token = generate_password_reset_token(prng_based);
      let used_prng = determine_if_token_is_prng_based(token);
      assert_eq!(prng_based, used_prng)
    }
  }
}
