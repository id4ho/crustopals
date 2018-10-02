pub mod crustopals {
  extern crate base64;
  extern crate hex;

  pub fn hex_to_b64(hex: &str) -> String {
    let decoded_hex = hex::decode(hex).expect("Invalid Hex!");
    base64::encode(&decoded_hex)
  }
}

#[cfg(test)]
mod tests {
  use crustopals::*;

  #[test]
  fn simple_hex_to_base64() {
    let hex = "ff00"; //    1111111100000000--------
    let base64 = "/wA="; // /     w     A     =
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
}
