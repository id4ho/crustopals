use crustopals::*;
use std::cmp::Ordering;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn solve_problem4() -> Result<(f32, String), String> {
  let f = File::open("4.txt").map_err(|e| e.to_string())?;
  let reader = BufReader::new(f);
  let lines_iter = reader.lines().map(|l| l.unwrap());

  let result = lines_iter
    .map(|line| problem3::solve_single_byte_xor(&line))
    .min_by(|(d1, _), (d2, _)| d1.partial_cmp(d2).unwrap_or(Ordering::Equal))
    .unwrap();
  Ok(result)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn solves_problem4() {
    let solution = solve_problem4().unwrap();
    assert_eq!("Now that the party is jumping\n", solution.1);
  }
}
