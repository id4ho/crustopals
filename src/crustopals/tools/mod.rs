extern crate base64;
extern crate hex;

pub mod aes;
pub mod freq_analysis;

// TODO: create struct for hex so as to be distinct from String.

pub fn hex_to_b64(hex: &str) -> String {
  let decoded_hex = hex::decode(hex).expect("Invalid Hex!");
  base64::encode(&decoded_hex)
}

pub fn bytes_to_string(bytes: Vec<u8>) -> String {
  bytes.into_iter().map(|b| b as char).collect::<String>()
}

pub fn xor_string(msg: &str, key: &str) -> String {
  let key = resize_key(key, msg.len());
  let xord_bytes = xor_bytes(msg.as_bytes(), key.as_bytes());
  bytes_to_string(xord_bytes)
}

pub fn xor_hex(hex_msg: &str, hex_key: &str) -> String {
  let hex_key = resize_key(hex_key, hex_msg.len());
  let message_bytes = hex::decode(hex_msg).expect("Message is invalid hex");
  let key_bytes = hex::decode(hex_key).expect("Key is invalid hex");
  let xord_bytes = xor_bytes(&message_bytes, &key_bytes);
  hex::encode(xord_bytes)
}

pub fn hamming_distance(bytes1: &[u8], bytes2: &[u8]) -> u32 {
  let mut distance: u32 = 0;
  for byte in xor_bytes(bytes1, bytes2) {
    distance += (byte as u64).count_ones();
  }
  distance
}

pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
  if a.len() != b.len() {
    panic!("Byte arrays not the same length!")
  };
  let mut xord_bytes: Vec<u8> = vec![];
  for (i, byte) in a.iter().enumerate() {
    xord_bytes.push(byte ^ b[i]);
  }
  xord_bytes
}

pub fn expand_bytes(bytes: &[u8], size: usize) -> Vec<u8> {
  let mut expanded_bytes: Vec<u8> = vec![];
  while { expanded_bytes.len() < size } {
    let bytes_needed = size - expanded_bytes.len();
    if bytes.len() < bytes_needed {
      expanded_bytes.extend(bytes.to_vec());
    } else {
      expanded_bytes.extend(bytes[0..bytes_needed].to_vec());
    }
  }
  expanded_bytes
}

fn resize_key(key: &str, size: usize) -> String {
  if key.len() == size {
    return String::from(key);
  }

  let mut resized_key = String::new();
  while { resized_key.len() < size } {
    let bytes_needed = size - resized_key.len();
    if key.len() < bytes_needed {
      resized_key.push_str(&key[0..]);
    } else {
      resized_key.push_str(&key[0..bytes_needed]);
    }
  }
  resized_key
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn simple_hex_to_base64() {
    let hex = "ff00"; //     111111 110000 0000-- ------
                      //     |      |      |      |
    let base64 = "/wA="; //  /      w      A      =
    let result = hex_to_b64(&hex);

    assert_eq!(result, base64);
  }

  #[test]
  fn convert_hex_to_base64() {
    let hex =
      "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e\
      6f7573206d757368726f6f6d";
    let base64 =
      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    let result = hex_to_b64(&hex);

    assert_eq!(result, base64);
  }

  #[test]
  fn simple_hex_string_xor() {
    let hex1 = "ff"; // 11111111
    let hex2 = "11"; // 00010001
    let xord = "ee"; // 11101110

    let result = xor_hex(&hex1, &hex2);

    assert_eq!(xord, result);
  }

  #[test]
  fn simple_string_xor() {
    let plaintext = String::from("Hello");
    let ciphertext = xor_string(&plaintext, "a");
    let ciphertext_bin_str: String = ciphertext
      .as_bytes()
      .into_iter()
      .map(|b| format!("{:08b}", b))
      .collect();

    // binary representation:
    // "Hello"   : 01001000 01100101 01101100 01101100 01101111
    // key ("a") : 01100001 01100001 01100001 01100001 01100001
    // ciphertext: 00101001 00000100 00001101 00001101 00001110

    assert_eq!(
      ciphertext_bin_str,
      "0010100100000100000011010000110100001110"
    );

    let converted_back_to_plaintext = xor_string(&ciphertext, "a");

    assert_eq!(converted_back_to_plaintext, plaintext)
  }

  #[test]
  fn xor_key_smaller_than_message() {
    let message = "9876"; // 1001100001110110
    let key = "f1"; //       1111000111110001
    let xord = "6987"; //    0110100110000111

    let result = xor_hex(&message, &key);

    assert_eq!(xord, result);
  }

  #[test]
  fn xor_key_larger_than_message() {
    let message = "98"; // 10011000
    let key = "f123"; //   1111000100100011
    let xord = "69"; //    01101001

    let result = xor_hex(&message, &key);

    assert_eq!(xord, result);
  }

  #[test]
  fn hex_string_xor() {
    let hex1 = "1c0111001f010100061a024b53535009181c";
    let hex2 = "686974207468652062756c6c277320657965";
    let xord = "746865206b696420646f6e277420706c6179";

    let result = xor_hex(&hex1, &hex2);

    assert_eq!(result, xord);
  }

  #[test]
  fn simple_hamming_distance() {
    let bytes1 = b"a"; // 01100001
    let bytes2 = b"b"; // 01100010

    let result = hamming_distance(bytes1, bytes2);

    assert_eq!(result, 2);
  }

  #[test]
  fn complex_hamming_distance() {
    let bytes1 = b"this is a test";
    let bytes2 = b"wokka wokka!!!";

    let result = hamming_distance(bytes1, bytes2);

    assert_eq!(result, 37);
  }

  #[test]
  fn it_expands_bytes() {
    let bytes = b"abc";

    assert_eq!(b"abcabc".to_vec(), expand_bytes(bytes, 6));
    assert_eq!(b"abcabca".to_vec(), expand_bytes(bytes, 7));
    assert_eq!(b"abcabcab".to_vec(), expand_bytes(bytes, 8));
    assert_eq!(b"ab".to_vec(), expand_bytes(bytes, 2));
  }
}
