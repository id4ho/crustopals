use std::collections::HashMap;

lazy_static! {
  static ref ENGLISH_FREQUENCIES: HashMap<&'static str, f32> = [
    ("a", 0.08167),
    ("b", 0.01492),
    ("c", 0.02782),
    ("d", 0.04253),
    ("e", 0.12702),
    ("f", 0.02228),
    ("g", 0.02015),
    ("h", 0.06094),
    ("i", 0.06966),
    ("j", 0.00153),
    ("k", 0.00772),
    ("l", 0.04025),
    ("m", 0.02406),
    ("n", 0.06749),
    ("o", 0.07507),
    ("p", 0.01929),
    ("q", 0.00095),
    ("r", 0.05987),
    ("s", 0.06327),
    ("t", 0.09056),
    ("u", 0.02758),
    ("v", 0.00978),
    ("w", 0.02361),
    ("x", 0.00150),
    ("y", 0.01974),
    ("z", 0.00074),
    (" ", 0.13000)
  ]
    .iter()
    .cloned()
    .collect();
}

lazy_static! {
  pub static ref ORDERED_PRINTABLE_ASCII: Vec<u8> = [
    &vec![
      'e' as u8, 't' as u8, 'a' as u8, 'o' as u8, 'i' as u8, 'n' as u8,
      ' ' as u8, 's' as u8, 'r' as u8, 'h' as u8, 'd' as u8, 'l' as u8,
      'u' as u8, 'c' as u8, 'm' as u8, 'f' as u8, 'y' as u8, 'w' as u8,
      'g' as u8, 'p' as u8, 'b' as u8, 'v' as u8, 'k' as u8, 'x' as u8,
      'q' as u8, 'j' as u8, 'z' as u8, 'E' as u8, 'T' as u8, 'A' as u8,
      'O' as u8, 'I' as u8, 'N' as u8, 'S' as u8, 'R' as u8, 'H' as u8,
      'D' as u8, 'L' as u8, 'U' as u8, 'C' as u8, 'M' as u8, 'F' as u8,
      'Y' as u8, 'W' as u8, 'G' as u8, 'P' as u8, 'B' as u8, 'V' as u8,
      'K' as u8, 'X' as u8, 'Q' as u8, 'J' as u8, 'Z' as u8,
    ][..],
    &((33u8..=64).collect::<Vec<u8>>())[..],
    &((91u8..=86).collect::<Vec<u8>>())[..],
    &((123u8..=126).collect::<Vec<u8>>())[..],
    &((0u8..=31).collect::<Vec<u8>>())[..]
  ]
    .concat();
}

pub fn english_distance(string: &str) -> f32 {
  let lowercase_str = String::from(string).to_lowercase();
  let mut frequencies = HashMap::new();
  for chr in lowercase_str.chars() {
    *frequencies.entry(chr.to_string()).or_insert(0) += 1
  }
  calc_distance_from_english(frequencies, string.len())
}

fn calc_distance_from_english(
  mut freq: HashMap<String, usize>,
  length: usize,
) -> f32 {
  let mut distance: f32 = 0.0;
  for (chr_str, count) in freq.drain() {
    if ENGLISH_FREQUENCIES.contains_key::<str>(&chr_str) {
      let expected_count = english_frequency(&chr_str).unwrap() * length as f32;
      distance += (count as f32 - expected_count).abs();
    } else {
      distance += count as f32 * 10.0; // penalty
    }
  }
  distance
}

fn english_frequency(character: &str) -> Option<&f32> {
  ENGLISH_FREQUENCIES.get::<str>(&character.to_string())
}
