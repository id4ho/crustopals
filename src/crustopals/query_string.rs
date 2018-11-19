use crustopals::tools::*;

lazy_static! {
  pub static ref PREPEND_STR: String =
    "comment1=cooking%20MCs;userdata=".to_string();
  pub static ref APPEND_STR: String =
    ";comment2=%20like%20a%20pound%20of%20bacon".to_string();
}

pub fn cbc_encrypt(key: &[u8], iv: &[u8], pt_bytes: &[u8]) -> Vec<u8> {
  let mut msg = PREPEND_STR.as_bytes().to_vec().clone();
  msg.extend(filter_pt(pt_bytes));
  msg.extend(APPEND_STR.as_bytes().to_vec());
  aes::encrypt_message_cbc(&msg, key, iv)
}

pub fn ctr_encrypt(key: &[u8], nonce: &[u8], pt_bytes: &[u8]) -> Vec<u8> {
  let mut msg = PREPEND_STR.as_bytes().to_vec().clone();
  msg.extend(filter_pt(pt_bytes));
  msg.extend(APPEND_STR.as_bytes().to_vec());
  aes::encrypt_ctr(&msg, key, nonce)
}

pub fn cbc_decrypt(key: &[u8], iv: &[u8], ct_bytes: &[u8]) -> Vec<u8> {
  aes::decrypt_message_cbc(&ct_bytes, key, iv).unwrap()
}

pub fn ctr_decrypt(key: &[u8], nonce: &[u8], ct_bytes: &[u8]) -> Vec<u8> {
  aes::decrypt_ctr(&ct_bytes, key, nonce)
}

pub fn filter_pt(bytes: &[u8]) -> Vec<u8> {
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

pub fn cbc_decrypts_with_admin_rights(
  key: &[u8],
  iv: &[u8],
  ct_bytes: &[u8],
) -> bool {
  let decrypted: Vec<u8> = cbc_decrypt(key, iv, ct_bytes);
  has_admin_rights(decrypted)
}

pub fn ctr_decrypts_with_admin_rights(
  key: &[u8],
  nonce: &[u8],
  ct_bytes: &[u8],
) -> bool {
  let decrypted: Vec<u8> = ctr_decrypt(key, nonce, ct_bytes);
  has_admin_rights(decrypted)
}

fn has_admin_rights(decrypted: Vec<u8>) -> bool {
  let admin_str = ";admin=true;".to_string();
  let admin_bytes = admin_str.as_bytes();
  for i in 0..(decrypted.len() - admin_bytes.len()) {
    if decrypted[i..(i + admin_bytes.len())] == admin_bytes[..] {
      return true;
    }
  }
  return false;
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_filters_equals_signs() {
    let bytes: Vec<u8> = vec!['=' as u8];
    let result = filter_pt(&bytes);

    assert_eq!(vec!['\'' as u8, '=' as u8, '\'' as u8], result);
  }

  #[test]
  fn it_filters_semicolons() {
    let bytes: Vec<u8> = vec![';' as u8];
    let result = filter_pt(&bytes);

    assert_eq!(vec!['\'' as u8, ';' as u8, '\'' as u8], result);
  }

  #[test]
  fn it_filters_equals_and_semicolons() {
    let key: Vec<u8> = aes::generate_key();
    let iv: Vec<u8> = aes::generate_iv();
    let string = ";admin=true;".to_string();
    let bytes: &[u8] = string.as_bytes();
    let ct = cbc_encrypt(&key, &iv, &bytes);
    let decrypted_bytes = cbc_decrypt(&key, &iv, &ct);

    assert_ne!(bytes.to_vec(), decrypted_bytes);
    assert!(!cbc_decrypts_with_admin_rights(&key, &iv, &ct));
  }
}
