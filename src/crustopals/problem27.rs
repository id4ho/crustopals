use crustopals::query_string;
use crustopals::tools::*;

lazy_static! {
    pub static ref RANDOM_KEY: Vec<u8> = aes::generate_key();
}

pub fn broken_cbc_encrypt(msg_bytes: &[u8]) -> Vec<u8> {
    query_string::cbc_encrypt(&RANDOM_KEY, &RANDOM_KEY, msg_bytes)
}

fn ascii_compliant_decrypt(ct: Vec<u8>) -> Result<Vec<u8>, (String, Vec<u8>)> {
    let decrypted = query_string::cbc_decrypt(&RANDOM_KEY, &RANDOM_KEY, &ct);

    if decrypted[..].is_ascii() {
        Ok(decrypted)
    } else {
        Err(("Invalid ascii".to_string(), decrypted))
    }
}

pub fn attack_broken_cbc(mut ct: Vec<u8>) -> Vec<u8> {
    for i in 0..32 {
        ct[i] = 0u8;
    }

    match ascii_compliant_decrypt(ct) {
        Ok(_) => panic!("Something went wrong.."),
        Err((_e, plaintext)) => {
            return xor_bytes(&plaintext[0..16], &plaintext[16..32]);
        }
    };
}

pub fn attack_broken_cbc_method2(mut ct: Vec<u8>) -> Vec<u8> {
    // set block 2 to all zeros
    for i in 16..32 {
        ct[i] = 0u8;
    }

    // set block 3 to block 1
    for i in 32..48 {
        ct[i] = ct[i - 32];
    }

    match ascii_compliant_decrypt(ct) {
        Ok(_) => panic!("Something went wrong.."),
        Err((_e, plaintext)) => {
            // xor the first and third pt blocks
            return xor_bytes(&plaintext[0..16], &plaintext[32..48]);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cracks_the_key_when_provided_the_noncompliant_ascii_decrypt() {
        let message = "OK".to_string();
        let msg_bytes = message.as_bytes();

        let ct = broken_cbc_encrypt(msg_bytes);
        let key: Vec<u8> = attack_broken_cbc(ct);

        assert_eq!(key, *RANDOM_KEY);
    }

    #[test]
    fn cracks_the_key_when_provided_the_noncompliant_ascii_decrypt2() {
        let message = "OK".to_string();
        let msg_bytes = message.as_bytes();

        let ct = broken_cbc_encrypt(msg_bytes);
        let key: Vec<u8> = attack_broken_cbc_method2(ct);

        assert_eq!(key, *RANDOM_KEY);
    }
}
