use crustopals::query_string;
use crustopals::tools::*;

lazy_static! {
  pub static ref RANDOM_KEY: Vec<u8> = aes::generate_key();
  pub static ref NONCE: Vec<u8> = aes::generate_rand_bytes(8);
}

pub fn attack_ctr_oracle() -> Vec<u8> {
  let attack_string = "\x00admin\x00true";
  let attack_bytes = attack_string.as_bytes().to_vec();
  let ct = query_string::ctr_encrypt(&RANDOM_KEY, &NONCE, attack_bytes);
  let mut bitflipped_ct = ct.clone();

  // 32 is the length of the prefix string
  bitflipped_ct[32] ^= ';' as u8;
  bitflipped_ct[32 + 6] ^= '=' as u8;
  bitflipped_ct
}

#[cfg(test)]
mod tests {
  use super::*;
  use crustopals::query_string::ctr_decrypts_with_admin_rights;

  #[test]
  fn cracks_ctr_with_padding_attack() {
    let crack_ctr_to_upgrade_to_admin = attack_ctr_oracle();
    let admin_rights = ctr_decrypts_with_admin_rights(
      &RANDOM_KEY,
      &NONCE,
      crack_ctr_to_upgrade_to_admin,
    );

    assert!(admin_rights);
  }
}
