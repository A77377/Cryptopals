use std::{error::Error, fs};

use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit},
    Aes128,
};

use crate::set2::challenge9::strip_pkcs_no7_padding;

use super::challenge6::base64_to_bytes;

pub fn aes_in_ecb_mode() -> Result<String, Box<dyn Error>> {
    let base64_str_ciphertext = fs::read_to_string("data/7.txt")
        .and_then(|s| Ok(s.replace("\n", "")))
        .expect("Error reading input file.");

    decrypt_aes_ecb_from_base64_ct(&base64_str_ciphertext, "YELLOW SUBMARINE".as_bytes())
}

pub fn decrypt_aes_ecb_from_base64_ct(
    base64_ct: &str,
    aes_key: &[u8],
) -> Result<String, Box<dyn Error>> {
    let ciphertext_bytes = base64_to_bytes(&base64_ct)?;
    let plaintext_bytes = dec_aes_ecb(&ciphertext_bytes, aes_key);
    let plaintext = String::from_utf8(plaintext_bytes)?;

    println!("{plaintext}");

    Ok(plaintext)
}

pub fn dec_aes_ecb(ciphertext_bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(key);
    let mut blocks = Vec::new();
    // Blocks will be the same size as the key (16 bytes = 128 bits)
    (0..ciphertext_bytes.len()).step_by(16).for_each(|offset| {
        blocks.push(GenericArray::clone_from_slice(
            // &ciphertext_bytes[offset..offset + 16],
            &ciphertext_bytes[offset..][..16],
        ))
    });
    cipher.decrypt_blocks(&mut blocks);
    let padded_pt = blocks.iter().flatten().cloned().collect::<Vec<u8>>();
    strip_pkcs_no7_padding(&padded_pt).to_vec()
    // padded_pt
}
