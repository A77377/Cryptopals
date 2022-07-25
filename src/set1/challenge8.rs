use std::{error::Error, fs};

use super::challenge1::hex_to_bytes;

const KEYSIZE: usize = 16; // 128 bits

pub fn detect_aes_ecb() -> Result<bool, Box<dyn Error>> {
    let mut ecb_detected = false;
    let hex_ciphertexts = fs::read_to_string("data/8.txt")?;
    for (line_no, hex_ct_line) in hex_ciphertexts.lines().enumerate() {
        let ciphertext_bytes = hex_to_bytes(hex_ct_line)?;
        if is_aes_ecb(&ciphertext_bytes) {
            println!("Line {line_no} has repeated blocks. As such, it may have been encrypted by a cipher in ECB mode.");
            println!("Line: {hex_ct_line}");
            ecb_detected = true;
        }
    }

    Ok(ecb_detected)
}

pub fn is_aes_ecb(ciphertext: &[u8]) -> bool {
    let total_number_of_blocks = ciphertext.len() / 16;
    let mut blocks = Vec::with_capacity(total_number_of_blocks);
    (0..ciphertext.len())
        .step_by(KEYSIZE)
        // .for_each(|offset| blocks.push(ciphertext[offset..offset + keysize].to_vec()));
        .for_each(|offset| blocks.push(ciphertext[offset..][..KEYSIZE].to_vec()));
    // These versions are maybe slightly slower according to hyperfine, but seem to be slower within a margin of error.
    // let unique_number_of_blocks = blocks.into_iter().collect::<HashSet<_>>().len();
    // let unique_number_of_blocks = blocks.into_iter().unique().count();
    blocks.sort();
    blocks.dedup();
    let unique_number_of_blocks = blocks.len();
    // let repeated_number_of_blocks = total_number_of_blocks - unique_number_of_blocks;
    total_number_of_blocks != unique_number_of_blocks
}
