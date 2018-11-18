use crustopals::query_string;
use crustopals::tools::*;

lazy_static! {
  pub static ref RANDOM_KEY: Vec<u8> = aes::generate_key();
  pub static ref IV: Vec<u8> = aes::generate_iv();
}

pub fn attack_cbc_oracle() -> Vec<u8> {
  // need to manipulate the third block of ct to adjust the \x00's to ; and =
  let attack_string = "superspecialdata\x00admin\x00true";
  let ct = query_string::cbc_encrypt(
    &RANDOM_KEY,
    &IV,
    attack_string.as_bytes().to_vec(),
  );
  let mut bitflipped_ct: Vec<u8> = vec![];
  for (i, block) in ct.chunks(16).enumerate() {
    if i == 2 {
      let with_flipped_bits =
        ";\x00\x00\x00\x00\x00=\x00\x00\x00\x00\x00\x00\x00\x00\x00";
      let flipped_block = xor_bytes(block, with_flipped_bits.as_bytes());
      bitflipped_ct.extend(flipped_block);
    } else {
      bitflipped_ct.extend(block);
    }
  }
  bitflipped_ct
}

#[cfg(test)]
mod tests {
  use super::*;
  use crustopals::query_string::cbc_decrypts_with_admin_rights;

  #[test]
  fn cracks_cbc_with_padding_attack() {
    let crack_cbc_to_upgrade_to_admin = attack_cbc_oracle();
    let admin_rights = cbc_decrypts_with_admin_rights(
      &RANDOM_KEY,
      &IV,
      crack_cbc_to_upgrade_to_admin,
    );

    assert!(admin_rights);
  }
}
