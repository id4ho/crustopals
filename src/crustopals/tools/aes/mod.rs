pub mod byte_operations;
mod key_schedule;
mod state_array;
mod word;

use self::byte_operations::*;
use self::key_schedule::KeySchedule;
use self::state_array::StateArray;
use self::word::Word;
use crustopals::tools;

pub fn encrypt_message_cbc(bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
  let round_keys = key_schedule(key);
  let padded_bytes = pad_bytes(bytes);
  let mut encrypted_message: Vec<u8> = vec![];
  for block in padded_bytes.chunks(16) {
    let prev_block = if encrypted_message.len() == 0 {
      StateArray::new(&iv)
    } else {
      let prev_block_start: usize = (encrypted_message.len() - 16) as usize;
      StateArray::new(&encrypted_message[prev_block_start..])
    };

    let mut state_array = StateArray::new(block);
    state_array.xor(&prev_block);
    let encrypted_block = encrypt_block(state_array, &round_keys);
    let result = encrypted_block.to_u8();
    encrypted_message.extend(result);
  }
  encrypted_message
}

pub fn encrypt_message_ecb(bytes: &[u8], key: &[u8]) -> Vec<u8> {
  let round_keys = key_schedule(key);
  let padded_bytes = pad_bytes(bytes);
  let mut encrypted_message: Vec<u8> = vec![];
  for block in padded_bytes.chunks(16) {
    let state_array = StateArray::new(block);
    let encrypted_block = encrypt_block(state_array, &round_keys);
    let result = encrypted_block.to_u8();
    encrypted_message.extend(result);
  }
  encrypted_message
}

pub fn decrypt_message_cbc(bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
  let decrypt_pre_xor = decrypt_message(bytes, key);
  let mut iv_with_ciphertext: Vec<u8> = vec![];
  iv_with_ciphertext.extend(iv.to_vec());
  iv_with_ciphertext.extend(bytes);
  iv_with_ciphertext.truncate(decrypt_pre_xor.len());
  let pt_with_padding = tools::xor_bytes(&decrypt_pre_xor, &iv_with_ciphertext);
  strip_padding(pt_with_padding)
}

fn decrypt_message(bytes: &[u8], key: &[u8]) -> Vec<u8> {
  let round_keys = key_schedule(key);
  let mut decrypted_message: Vec<u8> = vec![];
  for block in bytes.chunks(16) {
    let state_array = StateArray::new(block);
    let decrypted_block = decrypt_block(state_array, &round_keys);
    let result = decrypted_block.to_u8();
    decrypted_message.extend(result);
  }
  decrypted_message
}

pub fn decrypt_message_ecb(bytes: &[u8], key: &[u8]) -> Vec<u8> {
  let decrypted_message = decrypt_message(bytes, key);
  strip_padding(decrypted_message)
}

fn strip_padding(mut decrypted_bytes: Vec<u8>) -> Vec<u8> {
  let total = decrypted_bytes.len();
  let padding = decrypted_bytes[decrypted_bytes.len() - 1] as usize;
  decrypted_bytes.truncate(total - padding);
  decrypted_bytes
}

fn encrypt_block(mut state: StateArray, keys: &KeySchedule) -> StateArray {
  state.apply_round_key(keys.round_key(0));
  for round in 1..=10 {
    state.sbox_translate();
    state.shift_rows();
    if round != 10 {
      state.mix_columns();
    }
    state.apply_round_key(keys.round_key(round));
  }
  state
}

fn decrypt_block(mut state: StateArray, keys: &KeySchedule) -> StateArray {
  state.apply_round_key(keys.round_key(10));
  for round in (0..10).rev() {
    state.inv_shift_rows();
    state.inv_sbox_translate();
    state.apply_round_key(keys.round_key(round));
    if round != 0 {
      state.inv_mix_columns();
    }
  }
  state
}

pub fn key_schedule(key: &[u8]) -> KeySchedule {
  // takes 4 words (32 bits each) and transform them into 44 words
  if key.len() != 16 {
    panic!("Wrong size key. Must be 16 bytes.");
  }
  let mut expanded_key: Vec<Word> = vec![];

  for word in key.chunks(4) {
    expanded_key.push(Word::new(&word))
  }

  for word_idx in 4..44 {
    let word: Word;
    {
      let one_ago = &expanded_key[word_idx - 1];
      let four_ago = &expanded_key[word_idx - 4];
      if word_idx % 4 == 0 {
        let rconi = rcon(word_idx);
        let rot_and_sboxed = one_ago.rotated().sbox_mapped();
        word = four_ago.xor(&rot_and_sboxed).xor(&rconi);
      } else {
        word = one_ago.xor(four_ago);
      }
    }
    expanded_key.push(word);
  }

  KeySchedule::new(expanded_key)
}

fn pad_bytes(bytes: &[u8]) -> Vec<u8> {
  tools::pad_bytes(bytes, 16)
}

fn rcon(word_idx: usize) -> Word {
  Word::new(&[rc(word_idx / 4), 0 as u8, 0 as u8, 0 as u8])
}

fn rc(idx: usize) -> u8 {
  [1, 2, 4, 8, 16, 32, 64, 128, 27, 54][idx - 1] as u8
}

#[cfg(test)]
mod tests {
  extern crate base64;
  extern crate hex;

  use super::*;

  #[test]
  #[should_panic(expected = "Wrong size key. Must be 16 bytes.")]
  fn panics_with_wrong_keysize() {
    let key = b"Hello world";
    key_schedule(key);
  }

  #[test]
  fn expands_an_aes_key_into_round_keys() {
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let expanded_round_key_words = [
      "2b7e1516", "28aed2a6", "abf71588", "09cf4f3c", "a0fafe17", "88542cb1",
      "23a33939", "2a6c7605", "f2c295f2", "7a96b943", "5935807a", "7359f67f",
      "3d80477d", "4716fe3e", "1e237e44", "6d7a883b", "ef44a541", "a8525b7f",
      "b671253b", "db0bad00", "d4d1c6f8", "7c839d87", "caf2b8bc", "11f915bc",
      "6d88a37a", "110b3efd", "dbf98641", "ca0093fd", "4e54f70e", "5f5fc9f3",
      "84a64fb2", "4ea6dc4f", "ead27321", "b58dbad2", "312bf560", "7f8d292f",
      "ac7766f3", "19fadc21", "28d12941", "575c006e", "d014f9a8", "c9ee2589",
      "e13f0cc8", "b6630ca6",
    ];

    let computed_round_keys = key_schedule(&key);

    for (i, word) in expanded_round_key_words.iter().enumerate() {
      assert_eq!(
        computed_round_keys[i],
        Word::new(&hex::decode(word).unwrap())
      );
    }
  }

  #[test]
  fn encrypts_messages_in_cbc_mode() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let message = "here is the mess".as_bytes();
    let iv = [0 as u8; 16];
    let expected_ciphertext =
      base64::decode("nRGOqUe3iBURUPUe5NjYJTSrsoTAS1bzHKzpdPDcoFg=").unwrap();
    let encrypted = encrypt_message_cbc(message, key, &iv);

    assert_eq!(encrypted, expected_ciphertext);
  }

  #[test]
  fn decrypts_messages_in_cbc_mode() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = [0 as u8; 16];
    let ciphertext =
      base64::decode("nRGOqUe3iBURUPUe5NjYJTSrsoTAS1bzHKzpdPDcoFg=").unwrap();
    let aes_128_bit_decrypted = decrypt_message_cbc(&ciphertext, key, &iv);

    assert_eq!(aes_128_bit_decrypted, "here is the mess".as_bytes());
  }

  #[test]
  fn encrypts_messages_in_ecb_mode() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let message = "here is the mess".as_bytes();
    let expected_ciphertext =
      base64::decode("nRGOqUe3iBURUPUe5NjYJWD6NnB+RfSZ26DyW5IjAaU=").unwrap();
    let aes_128_bit_encrypted = encrypt_message_ecb(message, key);

    assert_eq!(aes_128_bit_encrypted, expected_ciphertext);
  }

  #[test]
  fn decrypts_messages_in_ecb_mode() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let ciphertext =
      base64::decode("nRGOqUe3iBURUPUe5NjYJWD6NnB+RfSZ26DyW5IjAaU=").unwrap();
    let aes_128_bit_decrypted = decrypt_message_ecb(&ciphertext, key);

    assert_eq!(aes_128_bit_decrypted, "here is the mess".as_bytes());
  }

  #[test]
  fn decrypts_ecb_test_message() {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let ciphertext = hex::decode(
      "69c4e0d86a7b0430d8cdb78070b4c55a954f64f2e4e86e9eee82d20216684899",
    ).unwrap();
    let plaintext = hex::decode("00112233445566778899aabbccddeeff").unwrap();
    let aes_128_bit_decrypted = decrypt_message_ecb(&ciphertext, &key);
    let aes_128_bit_encrypted = encrypt_message_ecb(&plaintext, &key);

    assert_eq!(ciphertext, aes_128_bit_encrypted);
    assert_eq!(aes_128_bit_decrypted, plaintext);
  }
}
