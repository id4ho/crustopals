use crustopals::tools::*;

lazy_static! {
  pub static ref RANDOM_KEY: Vec<u8> = aes::generate_key();
  pub static ref IV: Vec<u8> = aes::generate_iv();
  pub static ref PREPEND_STR: String =
    "comment1=cooking%20MCs;userdata=".to_string();
  pub static ref APPEND_STR: String =
    ";comment2=%20like%20a%20pound%20of%20bacon".to_string();
}

pub fn cbc_encrypt(pt_bytes: Vec<u8>) -> Vec<u8> {
  let mut msg = PREPEND_STR.as_bytes().to_vec().clone();
  msg.extend(filter_pt(pt_bytes));
  msg.extend(APPEND_STR.as_bytes().to_vec());
  aes::encrypt_message_cbc(&msg, &RANDOM_KEY.to_vec(), &IV.to_vec())
}

pub fn cbc_decrypt(ct_bytes: Vec<u8>) -> Vec<u8> {
  aes::encrypt_message_cbc(&ct_bytes, &RANDOM_KEY.to_vec(), &IV.to_vec())
}

pub fn ct_decrypts_with_admin_rights(ct_bytes: Vec<u8>) -> bool {
  let admin_str = ";admin=true;".to_string();
  let admin_bytes = admin_str.as_bytes();
  let decrypted: Vec<u8> = cbc_decrypt(ct_bytes);
  for i in 0..(decrypted.len() - admin_bytes.len()) {
    if decrypted[i..(i + admin_bytes.len())] == admin_bytes[..] {
      return true;
    }
  }
  return false;
}

pub fn attack_cbc_oracle() -> Vec<u8> {
  cbc_encrypt("hmm".as_bytes().to_vec())
}

pub fn filter_pt(bytes: Vec<u8>) -> Vec<u8> {
  let mut quoted_bytes: Vec<u8> = vec![];
  for b in bytes.iter() {
    if b == &(';' as u8) || b == &('=' as u8) {
      quoted_bytes.push('\'' as u8);
      quoted_bytes.push(*b);
      quoted_bytes.push('\'' as u8);
    } else {
      quoted_bytes.push(*b);
    }
  }
  quoted_bytes
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_filters_equals_signs() {
    let bytes: Vec<u8> = vec!['=' as u8];
    let result = filter_pt(bytes);

    assert_eq!(vec!['\'' as u8, '=' as u8, '\'' as u8], result);
  }

  #[test]
  fn it_filters_semicolons() {
    let bytes: Vec<u8> = vec![';' as u8];
    let result = filter_pt(bytes);

    assert_eq!(vec!['\'' as u8, ';' as u8, '\'' as u8], result);
  }

  #[test]
  fn it_filters_equals_and_semicolons() {
    let string = ";admin=true;".to_string();
    let bytes: &[u8] = string.as_bytes();
    let ct = cbc_encrypt(bytes.to_vec());
    let decrypted_bytes = cbc_decrypt(ct.clone());

    assert_ne!(bytes.to_vec(), decrypted_bytes);
    assert!(!ct_decrypts_with_admin_rights(ct));
  }

  #[test]
  fn cracks_cbc_with_padding_attack() {
    let crack_cbc_to_upgrade_to_admin = attack_cbc_oracle();
    let result = false;
    // let result = decrypted_includs_admin(crack_cbc_to_upgrade_to_admin);

    assert_eq!(true, result);
  }
}
