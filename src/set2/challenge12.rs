use rand;
use std::collections::BTreeMap;

use crate::set1::{challenge6, challenge8};
use crate::set2::challenge11;

// static mut ECB_KEY: [u8; 16] = [0; 16];

// pub unsafe fn set_ecb_key() {
//     ECB_KEY = rand::random()
// }

// One other technique to get confirmation for ECB and the block size is to simply generate
// known sequences of increasing size, for instance, repeating the same byte, like 'A' as u8.
// Eventually, even if there is padding at the head, 2 equal block sized chunks will appear.
// It might be difficult to detect the size of the block, as it would require a linear operation,
// trying to get two consecutive equal slices of bytes.

// One other possibility is to use PKCS#7 to get that information, since it adds a whole block of
// padding when input is aligned to the block size.

pub struct ECBOracle {
    aes_ecb_key: [u8; 16],
    bytes_to_append: Vec<u8>,
}

impl ECBOracle {
    pub fn new() -> Self {
        let pt_base64_str_to_append =
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
             aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
             dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
             YnkK";
        ECBOracle {
            aes_ecb_key: rand::random(),
            // I know the &str is valid Base64, so it is safe to unwrap.
            bytes_to_append: challenge6::base64_to_bytes(pt_base64_str_to_append).unwrap(),
        }
    }

    // Write a function that encrypts data under an unknown key ---
    // that is, a function that generates a random key and encrypts under it.
    pub fn enc_aes_ecb(&self, plaintext_bytes: &[u8]) -> Vec<u8> {
        let mut pt_bytes = Vec::with_capacity(plaintext_bytes.len() + self.bytes_to_append.len());
        pt_bytes.extend_from_slice(plaintext_bytes);
        pt_bytes.extend_from_slice(&self.bytes_to_append);
        // println!("First plaintext block: {:02x?}", &pt_bytes[..16]);

        // ECB mode now uses a fixed key.
        let ciphertext_bytes = challenge11::enc_aes_ecb(&pt_bytes, &self.aes_ecb_key);

        ciphertext_bytes
    }

    // Feed identical bytes of your-string to the function 1 at a time
    // --- start with 1 byte ("A"), then "AA", then "AAA" and so on.
    // Discover the block size of the cipher. You know it, but do this
    // step anyway.
    // This requires no head padding.
    pub fn find_block_size(&self) -> Option<usize> {
        let mut block_size = None;
        let inclusive_upper_bound = 32;
        let mut pt = Vec::with_capacity(inclusive_upper_bound);
        pt.push('A' as u8);
        let mut prev_ct = challenge11::enc_aes_ecb(&pt, &self.aes_ecb_key);
        for test_block_size in 2..=inclusive_upper_bound {
            // Fill the additional index with the known byte.
            pt.resize(test_block_size, 'A' as u8);
            let ct = challenge11::enc_aes_ecb(&pt, &self.aes_ecb_key);
            // Compare just the beggining of the ciphertexts. (The 4 is arbitrary.)
            // If nothing has changed, it means the first block remained the same.
            if ct[..4].eq(&prev_ct[..4]) {
                block_size = Some(test_block_size - 1);
                break;
            }
            prev_ct = ct;
        }
        block_size
    }
}

// Make a dictionary of every possible last byte by feeding different
// strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB",
// "AAAAAAAC", remembering the first block of each invocation.
/// Generates all possible corresponding ciphertext blocks from a plaintext block starting with one_short_chunk.
fn possible_ct_to_pt_blocks(
    one_short_chunk: &[u8],
    block_size: usize,
    ecb_oracle: &ECBOracle,
) -> BTreeMap<Vec<u8>, Vec<u8>> {
    // println!("\n Generating all possible ciphertexts for given plaintext block\n");
    let one_short_block_size = block_size - 1;
    assert_eq!(one_short_chunk.len(), one_short_block_size);
    let mut block = Vec::with_capacity(block_size);
    block.extend_from_slice(one_short_chunk);
    block.push(0); // Will be overwritten. Just for simplification.
    assert_eq!(block.len(), block_size);
    let mut ct_to_pt: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for byte in 0..=u8::MAX {
        block[one_short_block_size] = byte;
        assert_eq!(block.len(), block_size);
        let ct = ecb_oracle.enc_aes_ecb(&block);
        ct_to_pt.insert(ct[..block_size].to_vec(), block.clone());
        // println!("Matching ciphertext block: {:02x?}", &ct[..block_size]);
    }
    // println!("\n Done Generating all possible ciphertexts for given plaintext block\n");
    ct_to_pt
}

fn generate_all_ciphertexts(block_size: usize, ecb_oracle: &ECBOracle) -> Vec<Vec<u8>> {
    // println!("\n Generating all possible ciphertexts for different paddings\n");
    // Vector of ciphertexts for known header paddings of different lengths.
    let mut ciphertexts: Vec<Vec<u8>> = Vec::with_capacity(block_size);
    let mut padding = Vec::with_capacity(block_size - 1);
    for pad_size in (0..block_size).rev() {
        // println!("Padding with {pad_size} bytes");
        padding.resize(pad_size, 'A' as u8);
        let ct = ecb_oracle.enc_aes_ecb(&padding);
        ciphertexts.push(ct);
    }
    // println!("\n Done Generating all possible ciphertexts for different paddings\n");
    ciphertexts
}

fn detect_oracle_aes_ecb(block_size: usize, ecb_oracle: &ECBOracle) -> bool {
    let double_block_size = block_size * 2;
    let mut repeated_blocks = Vec::with_capacity(double_block_size);
    repeated_blocks.resize(double_block_size, 'A' as u8);
    let detect_ecb_ct_bytes = ecb_oracle.enc_aes_ecb(&repeated_blocks);
    challenge8::is_aes_ecb(&detect_ecb_ct_bytes)
}

fn find_payload_size(block_size: usize, ecb_oracle: &ECBOracle) -> usize {
    let mut prev_ct_size = ecb_oracle.enc_aes_ecb(&[]).len();
    let mut padding_size = 0;
    // Don't know the necessary capacity, so block_size is simply a hint.
    let mut head_pad = Vec::with_capacity(block_size);
    for head_pad_size in 1.. {
        head_pad.resize(head_pad_size, 'A' as u8);
        let cur_ct_size = ecb_oracle.enc_aes_ecb(&head_pad).len();
        // When this happens, the padding size + size of the payload align with a block-sized boundary.
        // as with PKCS#7 padding, a whole block of padding is added when this happens.
        if cur_ct_size != prev_ct_size {
            prev_ct_size = cur_ct_size;
            padding_size = head_pad_size;
            break;
        }
    }
    // The block_size here refers to the PKCS#7 padding when there's alignment with block size.
    prev_ct_size - block_size - padding_size
}

pub fn byte_at_a_time_ecb_dec() -> String {
    let ecb_oracle = ECBOracle::new();
    // Find block size
    let block_size = ecb_oracle.find_block_size().unwrap();
    // Detect ECB
    assert!(detect_oracle_aes_ecb(block_size, &ecb_oracle));
    // Find payload size
    let payload_size = find_payload_size(block_size, &ecb_oracle);

    // All the possible ciphertexts, given decreasing head padding.
    let all_ct_dec_pads = generate_all_ciphertexts(block_size, &ecb_oracle);

    // The obtained plaintext will be appended here.
    // The first (block_size - 1) bytes will be removed, as they are head padding.
    // Don't know the length of bytes in the sequence, so the requested capacity is arbitrary.
    let mut plaintext_byte_seq = Vec::with_capacity(2 * block_size);
    let one_short_block_size = block_size - 1;
    // Add head padding so thata sliding window can be formed over the first (block_size - 1) bytes.
    plaintext_byte_seq.resize(one_short_block_size, 'A' as u8);
    // Iterating through different offsets in the plaintext sequence of bytes,
    // generating a (block_size - 1)-sized sliding window.
    for ofst in 0..payload_size {
        let maybe_one_short_chunk = plaintext_byte_seq.get(ofst..ofst + one_short_block_size);
        if let Some(one_short_chunk) = maybe_one_short_chunk {
            assert_eq!(one_short_chunk.len(), one_short_block_size);
            // println!("One short chunk: {one_short_chunk:02x?}");

            let ct_to_pt_blocks =
                possible_ct_to_pt_blocks(one_short_chunk, block_size, &ecb_oracle);
            // println!("{ct_to_pt_blocks:#02x?}, len: {}", ct_to_pt_blocks.len());

            let ct_ndx = ofst % block_size;
            let ct = &all_ct_dec_pads[ct_ndx];
            let block_ndx = ofst / block_size;
            let block_start_byte_ndx = block_ndx * block_size;
            // println!("Offset: {ofst}, Block index: {block_ndx}, Ciphertext index = {ct_ndx}");
            let ct_block = &ct[block_start_byte_ndx..][..block_size];
            // println!("ct_block: {ct_block:02x?}");
            let pt_block = ct_to_pt_blocks
                .get(ct_block)
                .expect("There was no mapping for the given ciphertext block.");
            let last_byte = pt_block[one_short_block_size];
            // println!("Last byte: 0x{last_byte:02x} ({})", last_byte as char);
            plaintext_byte_seq.push(last_byte);
        } else {
            break;
        }
    }

    let payload_bytes = plaintext_byte_seq[one_short_block_size..].to_vec();
    // The bytes are expected to form a valid string.
    let payload_string = String::from_utf8(payload_bytes).unwrap();
    println!("> Payload:\n{payload_string}");
    payload_string
}
