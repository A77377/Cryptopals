use itertools::Itertools;

use super::{challenge1, challenge3};
use std::error::Error;
use std::fs;

pub fn detect_single_char_xor() -> Result<(), Box<dyn Error>> {
    let contents = fs::read_to_string("data/4.txt").expect("Error reading the file of ciphertexts.");

    let winner = contents
        .lines()
        .map(|line| challenge3::eff_single_byte_xor_cipher(line).unwrap_or(('_', f64::INFINITY)))
        .enumerate()
        .sorted_by(|(_i_a, (_ck_a, score_a)), (_i_b, (_ck_b, score_b))| {
            (*score_a)
                .partial_cmp(score_b)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .take(1)
        .next()
        .expect("No winner found");

    let winner_str = contents
        .lines()
        .take(winner.0 + 1)
        .last()
        .expect("No such ciphertext string.");
    let bytes = challenge1::hex_to_bytes(winner_str)?;
    let plaintext_bytes = challenge3::xor_bytes_with_char(&bytes, winner.1 .0)?;
    let plaintext_string = String::from_utf8(plaintext_bytes)?;
    println!("{:?}: {plaintext_string:?}", winner.1 .0);

    Ok(())
}
