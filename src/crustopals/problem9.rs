#[cfg(test)]
mod tests {
  extern crate hex;
  use crustopals::tools::*;

  #[test]
  fn pads_a_block() {
    let partial_block = "YELLOW SUBMARINE";
    let partial_block_hex = hex::encode(partial_block);
    let padded_bytes = pad_bytes(partial_block.as_bytes(), 20);
    let padded_hex = hex::encode(padded_bytes);
    let expected_result = format!("{}{}", partial_block_hex, "04".repeat(4));

    assert_eq!(expected_result, padded_hex);
  }

  #[test]
  fn adds_full_block_to_correctly_sized_block() {
    let partial_block = "YELLOW SUBMARINE";
    let partial_block_hex = hex::encode(partial_block);
    let padded_bytes = pad_bytes(partial_block.as_bytes(), 16);
    let padded_hex = hex::encode(padded_bytes);
    let expected_result = format!("{}{}", partial_block_hex, "10".repeat(16));

    assert_eq!(expected_result, padded_hex);
  }
}
