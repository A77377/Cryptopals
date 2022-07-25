use std::{error::Error, fs};

use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};

use crate::{set1::challenge6, set2::challenge9};

const BLOCK_SIZE: usize = 16;

/// CBC - Cipher Block Chaining - https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
pub fn cbc_mode() -> Result<(), Box<dyn Error>> {
    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = [0_u8; 16];
    let ciphertext_str = fs::read_to_string("data/10.txt")?;
    let ciphertext_bytes = challenge6::base64_to_bytes(&ciphertext_str.replace("\n", ""))?;

    let plaintext_bytes = dec_aes_cbc(key, &iv, &ciphertext_bytes);

    String::from_utf8(plaintext_bytes)?
        .lines()
        .for_each(|l| println!("{l}"));

    Ok(())
}

// iv - initialization vector
pub fn enc_aes_cbc(key: &[u8], iv: &[u8], plaintext_bytes: &[u8]) -> Vec<u8> {
    assert_eq!(iv.len(), BLOCK_SIZE);
    let key = GenericArray::from_slice(key);
    let cipher_core = Aes128::new(&key);
    let padded_plaintext_bytes = challenge9::append_pkcs_no7_padding(plaintext_bytes, BLOCK_SIZE);
    let mut xor_input = iv;
    let mut ciphertext_bytes = Vec::with_capacity(padded_plaintext_bytes.len());

    for offset in (0..padded_plaintext_bytes.len()).step_by(BLOCK_SIZE) {
        let pt_block = &padded_plaintext_bytes[offset..][..BLOCK_SIZE];
        let mut cipher_inout_block =
            GenericArray::from_iter(pt_block.iter().zip(xor_input.iter()).map(|(&a, &b)| a ^ b));
        cipher_core.encrypt_block(&mut cipher_inout_block);
        ciphertext_bytes.extend_from_slice(&cipher_inout_block);
        // XOR input for the next block
        xor_input = &ciphertext_bytes[offset..][..BLOCK_SIZE];
    }

    ciphertext_bytes
}

// iv - initialization vector
/// The `ciphertext_bytes` argument must have a length aligned with the block-size. 
pub fn dec_aes_cbc(key: &[u8], iv: &[u8], ciphertext_bytes: &[u8]) -> Vec<u8> {
    assert_eq!(iv.len(), BLOCK_SIZE);
    assert_eq!(ciphertext_bytes.len() % BLOCK_SIZE, 0);
    let key = GenericArray::from_slice(key);
    let cipher_core = Aes128::new(&key);
    let mut xor_input = iv;
    let mut padded_plaintext_bytes: Vec<u8> = Vec::with_capacity(ciphertext_bytes.len());
    let mut pt_block = [0; BLOCK_SIZE];

    for offset in (0..ciphertext_bytes.len()).step_by(BLOCK_SIZE) {
        let ct_block = &ciphertext_bytes[offset..][..BLOCK_SIZE];
        let mut cipher_inout_block = GenericArray::clone_from_slice(ct_block);
        cipher_core.decrypt_block(&mut cipher_inout_block);
        cipher_inout_block
            .iter()
            .zip(xor_input.iter())
            .map(|(&a, &b)| a ^ b)
            .enumerate()
            .for_each(|(i, pt_b)| pt_block[i] = pt_b);
        padded_plaintext_bytes.extend_from_slice(&pt_block);
        // XOR input for the next block
        xor_input = ct_block;
    }

    challenge9::strip_pkcs_no7_padding(&padded_plaintext_bytes).to_vec()
}
