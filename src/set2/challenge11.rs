use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes128,
};
use rand::{self, Rng};

use crate::set1::challenge8;
use crate::set2::{challenge10, challenge9};

// Write a function to generate a random AES key; that's just 16 random bytes.
pub fn generate_random_16_bytes() -> Vec<u8> {
    let mut aes_key = Vec::with_capacity(16);
    let mut rng = rand::thread_rng();
    for _ in 0..16 {
        aes_key.push(rng.gen())
    }
    aes_key
}

// Write a function that encrypts data under an unknown key ---
// that is, a function that generates a random key and encrypts under it.
pub fn encryption_oracle(plaintext_bytes: &[u8]) -> Vec<u8> {
    let aes_key = generate_random_16_bytes();
    // Under the hood, have the function append 5-10 bytes (count chosen randomly) before the
    // plaintext and 5-10 bytes after the plaintext.
    let mut rng = rand::thread_rng();
    // TODO head and tail padding should be equal of not?
    let (head_pad, tail_pad) = (rng.gen_range(5..10), rng.gen_range(5..10));
    let desired_len = plaintext_bytes.len() + head_pad + tail_pad;
    let mut padded_plaintext_bytes = Vec::with_capacity(desired_len);
    padded_plaintext_bytes.resize(desired_len, 0);
    for _ in 0..head_pad {
        rng.fill(&mut padded_plaintext_bytes[..head_pad]);
    }
    padded_plaintext_bytes[head_pad..][..plaintext_bytes.len()].copy_from_slice(&plaintext_bytes);
    for _ in 0..tail_pad {
        rng.fill(&mut padded_plaintext_bytes[(plaintext_bytes.len() + head_pad)..]);
    }

    // Now, have the function choose to encrypt under ECB 1/2 the time,
    // and under CBC the other half (just use random IVs each time for CBC).
    // Use rand(2) to decide which to use.
    let use_cbc = rng.gen_bool(0.5);
    let ciphertext_bytes = if use_cbc {
        let rand_iv = generate_random_16_bytes();
        challenge10::enc_aes_cbc(&aes_key, &rand_iv, &padded_plaintext_bytes)
    } else {
        enc_aes_ecb(&padded_plaintext_bytes, &aes_key)
    };

    ciphertext_bytes
}

pub fn enc_aes_ecb(plaintext_bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(key);
    let padded_pt = challenge9::append_pkcs_no7_padding(plaintext_bytes, 16);
    let mut blocks = Vec::new();
    // Generate plaintext blocks
    (0..padded_pt.len()).step_by(16).for_each(|offset| {
        blocks.push(GenericArray::clone_from_slice(&padded_pt[offset..][..16]));
    });
    cipher.encrypt_blocks(&mut blocks);
    blocks.iter().flatten().cloned().collect::<Vec<u8>>()
}

#[derive(Debug)]
pub enum BlockCipherMode {
    ECB, // Electronic codebook
    CBC, // Cipher block chaining
}

// Detect the block cipher mode the function is using each time.
// You should end up with a piece of code that, pointed at a block box
// that might be encrypting ECB or CBC, tells you which one is happening.
pub fn detect_block_cipher_mode() -> BlockCipherMode {
    let tries = 1_000;
    let mut results = Vec::with_capacity(tries);
    // Plaintext with repeated bytes
    let mut pt = Vec::with_capacity(50);
    pt.resize(50, 'A' as u8);
    for _ in 0..tries {
        let ct = encryption_oracle(&pt);
        if challenge8::is_aes_ecb(&ct) {
            results.push(BlockCipherMode::ECB);
            // println!("ECB");
        } else {
            results.push(BlockCipherMode::CBC);
            // println!("CBC");
        }
    }

    let mut cbc_count = 0;
    let mut ecb_count = 0;
    results.into_iter().for_each(|r| match r {
        BlockCipherMode::ECB => ecb_count += 1,
        BlockCipherMode::CBC => cbc_count += 1,
    });

    println!(
        "ECB: {ecb_count} / {tries} = {:.2}",
        ecb_count as f32 / tries as f32
    );
    println!(
        "CBC: {cbc_count} / {tries} = {:.2}",
        cbc_count as f32 / tries as f32
    );

    BlockCipherMode::CBC
}
