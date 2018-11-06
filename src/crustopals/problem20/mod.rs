use crustopals::problem19;
use crustopals::problem6;
// use crustopals::tools;

pub fn ciphertexts() -> Vec<Vec<u8>> {
  problem19::ciphertexts("src/crustopals/problem20/20.txt".to_string())
}

pub fn break_fixed_nonce_ctr() -> String {
  let mut cts = ciphertexts();
  truncate_to_shortest(&mut cts);
  let keysize = cts.first().unwrap().len();
  let bytes = cts.into_iter().flatten().collect();
  let (_, pt) = problem6::possible_solution_for_keysize(&bytes, keysize as u32);
  pt
}

fn find_min_length<T>(ciphertexts: &Vec<Vec<T>>) -> usize {
  let mut len = 0;
  for ct in ciphertexts.iter() {
    if ct.len() < len || len == 0 {
      len = ct.len();
    }
  }
  len
}

fn truncate_to_shortest<T>(cts: &mut Vec<Vec<T>>) {
  let len_of_shortest = find_min_length(&cts);
  for ct in cts.iter_mut() {
    ct.truncate(len_of_shortest);
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  // use crustopals::base64;
  use std::fs::File;
  use std::io::Read;
  // use std::io::{BufRead, BufReader, Write};

  #[test]
  fn it_returns_the_smallest_length_in_a_vector() {
    let vec: Vec<Vec<usize>> =
      vec![vec![1, 2, 3], vec![2, 3], vec![1], vec![2, 3]];

    assert_eq!(find_min_length(&vec), 1);
  }

  #[test]
  fn it_trucates_all_the_vectors() {
    let mut vec: Vec<Vec<usize>> =
      vec![vec![1, 2, 3], vec![2, 3], vec![3], vec![4, 5]];
    truncate_to_shortest(&mut vec);

    assert_eq!(vec, [[1], [2], [3], [4]]);
  }

  #[test]
  fn it_breaks_fixed_nonce_ctr() {
    let decrypted = break_fixed_nonce_ctr();
    let mut solution_file =
      File::open("src/crustopals/problem20/solution.txt").unwrap();
    let mut solutions = String::new();
    solution_file.read_to_string(&mut solutions).unwrap();

    assert_eq!(decrypted, solutions);
  }

  // #[test]
  // fn write_solution_to_file() {
  //   let file = File::open("src/crustopals/problem20/20.txt").unwrap();
  //   let mut solution_file =
  //     File::create("src/crustopals/problem20/solution.txt").unwrap();
  //   let reader = BufReader::new(file);
  //   for l in reader.lines() {
  //     let line = l.unwrap();
  //     let mut bytes = base64::decode(&line).unwrap();
  //     bytes.truncate(53);

  //     write!(solution_file, "{}", tools::bytes_to_string(bytes));
  //   }
  // }
}
