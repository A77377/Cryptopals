use std::error::Error;

use itertools::Itertools;

use super::{challenge3, challenge5::repeating_key_xor_bytes};
use std::fs;

fn get_base64_file_as_byte_vec(filepath: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let contents = fs::read_to_string(filepath)?;
    let joined_contents = contents
        .lines()
        .map(|s| s.trim_end().to_owned())
        .collect::<Vec<String>>()
        .join("");
    base64_to_bytes(&joined_contents)
}

#[derive(Debug)]
struct KeySizeScore {
    key_size: usize,
    score: f32,
}

fn factorial(n: usize) -> usize {
    if n == 1 {
        1
    } else {
        n * factorial(n - 1)
    }
}

fn guess_key_sizes(ciphertext_bytes: &[u8], num_guesses: usize) -> Vec<usize> {
    let (lower_bound_key_size, upper_bound_key_size) = (2, 40);
    let key_size_range_amplitude = upper_bound_key_size - lower_bound_key_size + 1;
    let key_size_range = lower_bound_key_size..=upper_bound_key_size;

    // The tupes of the vector are(keysize, hamming distance)
    let mut key_size_scores: Vec<KeySizeScore> = Vec::with_capacity(key_size_range_amplitude);
    // let slice_ranges = vec![slice_range_1, slice_range_2, slice_range_3, slice_range_4];
    let mut slice_ranges = Vec::with_capacity(4);
    let n = slice_ranges.capacity(); // total number of objects in the set
    let r = 2; // number of choosing objects from the set
    let number_of_combinations = (factorial(n) / (factorial(r) * factorial(n - r))) as f32;

    // Key size to be tested
    for key_size in key_size_range {
        let slice_range_1 = 0..key_size;
        let slice_range_2 = (key_size)..(2 * key_size);
        let slice_range_3 = (2 * key_size)..(3 * key_size);
        let slice_range_4 = (3 * key_size)..(4 * key_size);
        slice_ranges.push(slice_range_1);
        slice_ranges.push(slice_range_2);
        slice_ranges.push(slice_range_3);
        slice_ranges.push(slice_range_4);
        let slice_range_combinations = slice_ranges.iter().tuple_combinations();

        let mut normalized_hamming_dists_sum = 0.;

        for (range_a, range_b) in slice_range_combinations.into_iter() {
            let normalized_hamming_distance = hamming_distance_bytes(
                &ciphertext_bytes[range_a.clone()],
                &ciphertext_bytes[range_b.clone()],
            ) as f32
                / key_size as f32;
            normalized_hamming_dists_sum += normalized_hamming_distance;
        }

        key_size_scores.push(KeySizeScore {
            key_size,
            score: normalized_hamming_dists_sum / number_of_combinations,
        });

        // Clean-up, to avoid repeated allocations
        slice_ranges.clear();
    }

    key_size_scores.sort_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    key_size_scores[..num_guesses]
        .iter()
        .map(|x| x.key_size)
        .collect::<Vec<usize>>()
}

pub fn break_repeating_key_xor() -> Result<(String, String), Box<dyn Error>> {
    let ciphertext_bytes = get_base64_file_as_byte_vec("data/6.txt")?;

    let num_guesses = 5;
    let candidate_key_sizes = guess_key_sizes(&ciphertext_bytes, num_guesses);
    // Keys and respective aggregate scores
    let mut guessed_keys = Vec::with_capacity(num_guesses);

    for candidate_key_size in candidate_key_sizes {
        let candidate_key = guess_key(candidate_key_size, &ciphertext_bytes);
        guessed_keys.push(candidate_key);
    }
    // Sort by ascending order and select winner key.
    guessed_keys.sort_by(|a, b| {
        a.norm_agg_score
            .partial_cmp(&b.norm_agg_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let key = guessed_keys
        .into_iter()
        .next()
        .map(|gk| gk.key)
        .expect("No key was found for the ciphertext");

    // Repeated-key XOR on the ciphertext to obtain plaintext.
    let plaintext = repeating_key_xor_bytes(&ciphertext_bytes, &key);

    // (key, plaintext)
    Ok((String::from_utf8(key)?, String::from_utf8(plaintext)?))
}

#[derive(Debug)]
struct GuessedKey {
    key: Vec<u8>,
    norm_agg_score: f64,
}

fn guess_key(key_size: usize, ciphertext_bytes: &[u8]) -> GuessedKey {
    let mut key = Vec::with_capacity(key_size);
    let mut agg_score = 0.;
    for offset in 0..key_size {
        let mut same_key_bytes = Vec::new();
        let mut index = offset;
        let mut cursor = ciphertext_bytes.get(index);
        while cursor.is_some() {
            same_key_bytes.push(*cursor.unwrap());
            index += key_size;
            cursor = ciphertext_bytes.get(index);
        }
        let key_score = challenge3::eff_single_byte_xor_cipher_bytes(&same_key_bytes).unwrap();
        key.push(key_score.key);
        agg_score += key_score.score;
    }
    GuessedKey {
        key,
        norm_agg_score: agg_score / key_size as f64,
    }
}

// I do not like this ugly code.
pub fn base64_to_bytes(base64_str: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut res = Vec::with_capacity((base64_str.len() * 3) / 4);
    let mut base64_char_iter = base64_str.chars();

    let mut fst_cursor = base64_char_iter.next();
    while fst_cursor.is_some() {
        let fst_char_byte = base64_char_to_byte(fst_cursor.unwrap())?;

        let snd_cursor = base64_char_iter.next();
        let snd_char_byte = if let Some(sc) = snd_cursor {
            base64_char_to_byte(sc)?
        } else {
            return Err(From::from(
                "Could not form byte due to lack of Base64 characters.",
            ));
        };

        let snd_cursor = base64_char_iter.next();
        let mut trd_char_padding = None;
        let trd_char_byte = if let Some(tc) = snd_cursor {
            if tc == '=' {
                trd_char_padding = Some(());
            }
            base64_char_to_byte(tc)?
        } else {
            trd_char_padding = Some(());
            0
        };

        let fth_cursor = base64_char_iter.next();
        let mut fth_char_padding = None;
        let fth_char_byte = if let Some(fc) = fth_cursor {
            if fc == '=' {
                fth_char_padding = Some(());
            }
            base64_char_to_byte(fc)?
        } else {
            fth_char_padding = Some(());
            0
        };

        let fst_byte = (fst_char_byte << 2) | ((snd_char_byte >> 4) & 0x3);
        let snd_byte = ((snd_char_byte & 0xf) << 4) | ((trd_char_byte >> 2) & 0xf);
        let trd_byte = ((trd_char_byte & 0x3) << 6) | (fth_char_byte & 0x3f);

        res.push(fst_byte);
        if trd_char_padding.is_none() {
            res.push(snd_byte);
            if fth_char_padding.is_none() {
                res.push(trd_byte);
            }
        }
        fst_cursor = base64_char_iter.next();
    }

    Ok(res)
}

pub fn hamming_distance_str(string_a: &str, string_b: &str) -> usize {
    string_a
        .as_bytes()
        .into_iter()
        .zip(string_b.as_bytes().into_iter())
        .map(|(byte_a, byte_b)| *byte_a ^ *byte_b)
        .map(count_set_bits_u8)
        .sum::<usize>()
}

pub fn hamming_distance_str_wrapper(string_a: &str, string_b: &str) -> usize {
    hamming_distance_bytes(string_a.as_bytes(), string_b.as_bytes())
}

pub fn hamming_distance_bytes(bytes_a: &[u8], bytes_b: &[u8]) -> usize {
    bytes_a
        .into_iter()
        .zip(bytes_b.into_iter())
        .map(|(byte_a, byte_b)| *byte_a ^ *byte_b)
        .map(count_set_bits_u8)
        .sum::<usize>()
}

pub fn count_set_bits_u8(mut bit_block: u8) -> usize {
    bit_block = bit_block - ((bit_block >> 1) & 0x55);
    bit_block = ((bit_block >> 2) & 0x33) + (bit_block & 0x33);
    (((bit_block >> 4) + bit_block) & 0x0F) as usize
}

pub fn count_set_bits(mut n: u32) -> usize {
    n = n - ((n >> 1) & 0x55555555); // reuse input as temporary
    n = (n & 0x33333333) + ((n >> 2) & 0x33333333); // temp
    (((n + (n >> 4) & 0xF0F0F0F) * 0x1010101) >> 24) as usize // count
}

fn base64_char_to_byte(base64_char: char) -> Result<u8, Box<dyn Error>> {
    match base64_char {
        'A' => Ok(0b000000),
        'B' => Ok(0b000001),
        'C' => Ok(0b000010),
        'D' => Ok(0b000011),
        'E' => Ok(0b000100),
        'F' => Ok(0b000101),
        'G' => Ok(0b000110),
        'H' => Ok(0b000111),
        'I' => Ok(0b001000),
        'J' => Ok(0b001001),
        'K' => Ok(0b001010),
        'L' => Ok(0b001011),
        'M' => Ok(0b001100),
        'N' => Ok(0b001101),
        'O' => Ok(0b001110),
        'P' => Ok(0b001111),
        'Q' => Ok(0b010000),
        'R' => Ok(0b010001),
        'S' => Ok(0b010010),
        'T' => Ok(0b010011),
        'U' => Ok(0b010100),
        'V' => Ok(0b010101),
        'W' => Ok(0b010110),
        'X' => Ok(0b010111),
        'Y' => Ok(0b011000),
        'Z' => Ok(0b011001),
        'a' => Ok(0b011010),
        'b' => Ok(0b011011),
        'c' => Ok(0b011100),
        'd' => Ok(0b011101),
        'e' => Ok(0b011110),
        'f' => Ok(0b011111),
        'g' => Ok(0b100000),
        'h' => Ok(0b100001),
        'i' => Ok(0b100010),
        'j' => Ok(0b100011),
        'k' => Ok(0b100100),
        'l' => Ok(0b100101),
        'm' => Ok(0b100110),
        'n' => Ok(0b100111),
        'o' => Ok(0b101000),
        'p' => Ok(0b101001),
        'q' => Ok(0b101010),
        'r' => Ok(0b101011),
        's' => Ok(0b101100),
        't' => Ok(0b101101),
        'u' => Ok(0b101110),
        'v' => Ok(0b101111),
        'w' => Ok(0b110000),
        'x' => Ok(0b110001),
        'y' => Ok(0b110010),
        'z' => Ok(0b110011),
        '0' => Ok(0b110100),
        '1' => Ok(0b110101),
        '2' => Ok(0b110110),
        '3' => Ok(0b110111),
        '4' => Ok(0b111000),
        '5' => Ok(0b111001),
        '6' => Ok(0b111010),
        '7' => Ok(0b111011),
        '8' => Ok(0b111100),
        '9' => Ok(0b111101),
        '+' => Ok(0b111110),
        '/' => Ok(0b111111),
        '=' => Ok(0b000000),
        _ => Err(From::from(
            "Invalid byte: the given byte does not produce a Base64 character.",
        )),
    }
}
