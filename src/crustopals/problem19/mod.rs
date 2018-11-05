use crustopals::base64;
use crustopals::tools;
use std::cmp;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn ciphertexts() -> Vec<Vec<u8>> {
  // using randomly genreated keys and nonces, but hard coding for purpose of
  // exercise.
  let key: Vec<u8> = vec![
    197, 248, 107, 98, 164, 254, 30, 153, 250, 41, 99, 32, 59, 15, 76, 220,
  ]; // tools::aes::generate_key();
  let nonce: Vec<u8> = vec![144, 226, 242, 95, 221, 181, 68, 198]; // tools::aes::generate_rand_bytes(8);
  let mut ciphertexts: Vec<Vec<u8>> = vec![];
  let file = File::open("src/crustopals/problem19/19.txt").unwrap();
  let reader = BufReader::new(file);
  for l in reader.lines() {
    let line = l.unwrap();
    let bytes = base64::decode(&line).unwrap();
    ciphertexts.push(tools::aes::encrypt_ctr(&bytes, &key, &nonce));
  }
  ciphertexts
}

pub fn targeted_guess(cts: Vec<Vec<u8>>) {
  let guess = "turn:".as_bytes();
  let relevant_ct = &cts[37];
  let start_idx = 33;
  let keystream_fragment = tools::xor_bytes(
    &relevant_ct[start_idx..(start_idx + guess.len())],
    &guess,
  );
  let mut test_decrypts: Vec<u8> = vec![];
  println!("keystream is {:?}", keystream_fragment);
  for ct2 in cts.iter() {
    if ct2.len() > start_idx {
      let num_bytes = cmp::min(ct2.len() - start_idx, guess.len());
      let bytes = tools::xor_bytes(
        &keystream_fragment[0..num_bytes],
        &ct2[start_idx..(start_idx + num_bytes)],
      );
      test_decrypts.extend(&bytes);
    }
  }
  all_ascii(test_decrypts);
}

pub fn try_guess(cts: Vec<Vec<u8>>) {
  let guess = " head".as_bytes();
  for ct in cts.iter() {
    for i in 0..(ct.len() - guess.len() + 1) {
      let mut test_decrypts: Vec<u8> = vec![];
      let keystream_fragment =
        tools::xor_bytes(&ct[i..(i + guess.len())], &guess);
      for ct2 in cts.iter() {
        if ct2.len() > i {
          let num_bytes = cmp::min(ct2.len() - i, guess.len());
          let bytes = tools::xor_bytes(
            &keystream_fragment[0..num_bytes],
            &ct2[i..(i + num_bytes)],
          );
          test_decrypts.extend(&bytes);
        }
      }
      if human_readable(test_decrypts) {
        println!(
          "likely keystream fragment {:?} starting at {}",
          keystream_fragment, i
        );
      }
    }
  }
}

fn human_readable(bytes: Vec<u8>) -> bool {
  let mut undesirables = 0;
  for b in bytes {
    if b != 39
      && b != 44
      && b != 46
      && b != 32
      && b != 59
      && !(b > 64 && b < 91)
      && !(b > 96 && b < 123)
    {
      undesirables += 1;
    }
  }
  if undesirables < 1 {
    true
  } else {
    false
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::collections::HashMap;

  #[test]
  fn scratch_test_for_piecemeal_attack() {
    let ciphertexts = ciphertexts();
    // try_guess(ciphertexts);
    targeted_guess(ciphertexts);
    assert_eq!(1, 2);
  }

  #[test]
  fn print_substitutions() {
    let mut subs: HashMap<usize, Vec<u8>> = HashMap::new();
    subs.insert(0, vec![187, 167, 47, 25, 189]);
    subs.insert(5, vec![131, 239, 54, 43, 236]);
    subs.insert(10, vec![175, 98, 41, 61, 31]);
    subs.insert(15, vec![127, 166, 61, 17, 139]);
    subs.insert(20, vec![166, 196, 26, 86, 116]);
    subs.insert(25, vec![195, 21, 150, 171, 98]);
    subs.insert(30, vec![17, 156, 238, 218, 48]);
    subs.insert(35, vec![101, 128, 43]);

    let ciphertexts = ciphertexts();
    let mut renderable_ciphertexts = ciphertexts.clone();
    for renderable_ct in renderable_ciphertexts.iter_mut() {
      for i in 0..renderable_ct.len() {
        renderable_ct[i] = '.' as u8;
      }
    }

    for (start_idx, stream_segment) in subs {
      for (i, renderable_ct) in renderable_ciphertexts.iter_mut().enumerate() {
        if renderable_ct.len() > start_idx {
          // } + stream_segment.len()) {
          let num_bytes =
            cmp::min(renderable_ct.len() - start_idx, stream_segment.len());
          let changed_segment = tools::xor_bytes(
            &ciphertexts[i][start_idx..(start_idx + num_bytes)],
            &stream_segment[0..num_bytes],
          );
          for i in 0..num_bytes {
            renderable_ct[i + start_idx] = changed_segment[i];
          }
        }
      }
    }

    for (i, ct) in renderable_ciphertexts.into_iter().enumerate() {
      println!("{}: {}", i, tools::bytes_to_string(ct));
    }

    assert_eq!(1, 2);
  }
}
