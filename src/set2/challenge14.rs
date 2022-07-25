use rand::{self, Rng};
use std::collections::BTreeMap;

use crate::set1::{challenge6, challenge8};
use crate::set2::challenge11;

pub struct RandomHeadECBOracle {
    aes_ecb_key: [u8; 16],
    random_head_pad: Vec<u8>,
    target_tail_bytes: Vec<u8>,
}

impl RandomHeadECBOracle {
    pub fn new() -> Self {
        let pt_base64_str_to_append =
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
             aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
             dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
             YnkK";
        let mut rng = rand::thread_rng();
        // I chose the u8 range just for possible debugging simplicity, in case
        // I have to print anything.
        // let random_head_pad_size = rng.gen::<u8>() as usize;
        let random_head_pad_size = 33;
        let random_head_pad = (0..random_head_pad_size)
            .map(|_| rng.gen::<u8>())
            .collect::<Vec<u8>>();

        Self {
            aes_ecb_key: rand::random(),
            random_head_pad,
            // I know the &str is valid Base64, so it is safe to unwrap.
            target_tail_bytes: challenge6::base64_to_bytes(pt_base64_str_to_append).unwrap(),
        }
    }

    // Write a function that encrypts data under an unknown key ---
    // that is, a function that generates a random key and encrypts under it.
    pub fn enc_aes_ecb(&self, plaintext_bytes: &[u8]) -> Vec<u8> {
        let mut pt_bytes = Vec::with_capacity(
            self.random_head_pad.len() + plaintext_bytes.len() + self.target_tail_bytes.len(),
        );
        pt_bytes.extend_from_slice(&self.random_head_pad);
        pt_bytes.extend_from_slice(plaintext_bytes);
        pt_bytes.extend_from_slice(&self.target_tail_bytes);
        // println!("First plaintext block: {:02x?}", &pt_bytes[..16]);

        // ECB mode now uses a fixed key.
        let ciphertext_bytes = challenge11::enc_aes_ecb(&pt_bytes, &self.aes_ecb_key);

        ciphertext_bytes
    }

    pub fn find_block_size(&self) -> Option<usize> {
        let mut block_size = None;
        let mut pt = Vec::new();
        let prev_ct_size = self.enc_aes_ecb(&pt).len();
        for s in 1.. {
            pt.resize(s, 'i' as u8);
            let cur_ct_size = self.enc_aes_ecb(&pt).len();
            if cur_ct_size != prev_ct_size {
                // println!("Change at {s} bytes");
                block_size = Some(cur_ct_size - prev_ct_size);
                break;
            }
        }
        block_size
    }

    /*
    From https://cryptopals.com/sets/2/challenges/14

    "What's harder than challenge #12 about doing this?
     How would you overcome that obstacle?
     The hint is: you're using all the tools you already have; no crazy math is required.
     Think "STIMULUS" and "RESPONSE"."

    What's harder than challenge #12 is to the size of the target payload, for which we need
    to know the size of the random header.
    */

    // Block index = changing_block_start_idx / block size
    /// Finds the start index of the block where target bytes are inserted.
    pub fn find_target_block_start(&self) -> usize {
        // ab - attacker bytes
        let empty_ab_ct = self.enc_aes_ecb(&[]);
        let one_ab_ct = self.enc_aes_ecb(&['i' as u8]);

        let opt_ct_byte = empty_ab_ct
            .into_iter()
            .zip(one_ab_ct.into_iter())
            .enumerate()
            .skip_while(|(_, (e_ct, o_ct))| e_ct == o_ct)
            .next();
        let (target_block_start_ndx, _) = opt_ct_byte.unwrap();
        target_block_start_ndx
    }

    /// Finds the index within a block where attacker bytes are inserted.
    pub fn find_attack_offset(&self, block_size: usize) -> usize {
        let mut attacker_bytes = Vec::with_capacity(block_size);
        let target_block_start_ndx = self.find_target_block_start();
        let mut prev_target_block =
            self.enc_aes_ecb(&[])[target_block_start_ndx..][..block_size].to_owned();
        let mut atck_ofst = 0;

        for o in 1..=(block_size + 1) {
            attacker_bytes.push('i' as u8);
            let cur_target_block = self.enc_aes_ecb(&attacker_bytes)[target_block_start_ndx..]
                [..block_size]
                .to_owned();
            if cur_target_block == prev_target_block {
                atck_ofst = block_size - (o - 1);
                break;
            }
            prev_target_block = cur_target_block;
        }

        atck_ofst
    }

    /// Finds the size of the random header bytes appended to the remaining plaintext by the oracle.
    pub fn find_random_header_size(&self, block_size: usize) -> usize {
        let target_block_start_ndx = self.find_target_block_start();
        let attack_offset = self.find_attack_offset(block_size);
        target_block_start_ndx + attack_offset
    }

    /// Finds the size of the payload that follows the random header and possible attacker-controlled bytes.
    pub fn find_payload_size(&self, block_size: usize) -> usize {
        let random_header_size = self.find_random_header_size(block_size);

        let mut prev_ct_size = self.enc_aes_ecb(&[]).len();
        let mut known_pt_size = 0;
        // Don't know the necessary capacity, so block_size is simply a hint.
        let mut attacker_bytes = Vec::with_capacity(block_size);
        for attacker_bytes_size in 1.. {
            attacker_bytes.resize(attacker_bytes_size, 'i' as u8);
            let cur_ct_size = self.enc_aes_ecb(&attacker_bytes).len();
            // When this happens, the padding size + size of the payload align with a block-sized boundary.
            // as with PKCS#7 padding, a whole block of padding is added when this happens.
            if cur_ct_size != prev_ct_size {
                prev_ct_size = cur_ct_size;
                known_pt_size = attacker_bytes_size;
                break;
            }
        }
        (prev_ct_size - block_size) - (random_header_size + known_pt_size)
    }

    pub fn detect_oracle_aes_ecb(&self, block_size: usize) -> bool {
        let attack_ofst = self.find_attack_offset(block_size);
        let fill_size = block_size - attack_ofst;
        // dbg!(&attack_ofst, &fill_size);
        let attacker_bytes_size = fill_size + (block_size * 2);
        // dbg!(&attacker_bytes_size);
        let mut attacker_bytes = Vec::with_capacity(attacker_bytes_size);
        attacker_bytes.resize(attacker_bytes_size, 'i' as u8);
        // dbg!(&attacker_bytes, &attacker_bytes.len());
        let detect_ecb_ct_bytes = self.enc_aes_ecb(&attacker_bytes);
        challenge8::is_aes_ecb(&detect_ecb_ct_bytes)
    }

    fn generate_all_ciphertexts(&self, block_size: usize) -> Vec<Vec<u8>> {
        let attack_ofst = self.find_attack_offset(block_size);
        let fill_size = block_size - attack_ofst;
        // println!("\n Generating ciphertexts for all possible different paddings\n");
        // Vector of ciphertexts for known plaintexts of different lengths.
        let mut ciphertexts: Vec<Vec<u8>> = Vec::with_capacity(block_size);
        let mut known_pt = Vec::with_capacity(fill_size + block_size - 1);
        // Fill the first block where the attacker bytes are placed, so that it is later
        // possible to know all the bytes in the following block, to discover the target bytes.
        // In case attack_ofst was 0, it would be possible to just use the first block for the
        // extraction of the target bytes. However, this way simplifies things, as there is no
        // branching for that special case.
        known_pt.resize(fill_size, 'i' as u8);
        for pad_size in (0..block_size).rev() {
            // println!("Padding with {pad_size} bytes");
            known_pt.resize(fill_size + pad_size, 'i' as u8);
            let ct = self.enc_aes_ecb(&known_pt);
            // println!("PT: {:02x?}", Paint::rgb(186, 49, 160, &known_pt));
            // println!("CT: {:02x?}", Paint::magenta(&ct));
            ciphertexts.push(ct);
        }
        // println!(
        //     "\n {} Generating ciphertexts for all possible different paddings\n",
        //     Paint::green("Done")
        // );
        ciphertexts
    }

    // Make a dictionary of every possible last byte by feeding different
    // strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB",
    // "AAAAAAAC", remembering the appropriate block of each invocation.
    /// Generates all possible corresponding ciphertext blocks from a plaintext block starting with one_short_chunk.
    fn possible_ct_to_pt_blocks(
        &self,
        one_short_chunk: &[u8],
        block_size: usize,
    ) -> BTreeMap<Vec<u8>, Vec<u8>> {
        // println!("\n Generating all possible ciphertexts for given plaintext block\n");
        let target_block_start = self.find_target_block_start();
        let next_block_start = target_block_start + block_size;
        let attack_ofst = self.find_attack_offset(block_size);
        let fill_size = block_size - attack_ofst;
        let one_short_block_size = block_size - 1;
        let known_pt_last_ndx = fill_size + one_short_block_size;
        assert_eq!(one_short_chunk.len(), one_short_block_size);
        let mut known_pt = Vec::with_capacity(fill_size + block_size);
        known_pt.resize(fill_size, 'i' as u8);
        // dbg!(fill_size);
        known_pt.extend_from_slice(one_short_chunk);
        known_pt.push(0); // Will be overwritten. Just for simplification.
        assert_eq!(known_pt.len(), fill_size + block_size);
        let mut ct_to_pt: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        for byte in 0..=u8::MAX {
            known_pt[known_pt_last_ndx] = byte;
            // println!("{} {:02x?}", Paint::red("Known plaintext:"), &known_pt);
            assert_eq!(known_pt.len(), fill_size + block_size);
            let ct = self.enc_aes_ecb(&known_pt);
            ct_to_pt.insert(
                ct[next_block_start..][..block_size].to_vec(),
                known_pt[fill_size..][..block_size].to_vec(),
            );
            // println!(
            //     "{} {:02x?} -> {:02x?}",
            //     Paint::yellow("Matching ciphertext block:").underline(),
            //     Paint::blue(&known_pt[fill_size..][..block_size]),
            //     Paint::cyan(&ct[next_block_start..][..block_size])
            // );
        }
        // println!(
        //     "\n {} Generating all possible ciphertexts for given plaintext block\n",
        //     Paint::green("Done")
        // );
        ct_to_pt
    }
}

pub fn byte_at_a_time_ecb_dec() -> () {
    let ecb_oracle = RandomHeadECBOracle::new();
    // Find block size
    let block_size = ecb_oracle.find_block_size().unwrap();
    // Detect ECB
    assert!(ecb_oracle.detect_oracle_aes_ecb(block_size));
    // Find payload size
    let payload_size = ecb_oracle.find_payload_size(block_size);
    // Find the size of the random header padding
    let random_hdr_size = ecb_oracle.find_random_header_size(block_size);

    // Find target block start index (the block where the attacker bytes are first plced in)
    let target_block_start_ndx = ecb_oracle.find_target_block_start();
    let next_block_start_ndx = target_block_start_ndx + block_size;
    // Find offset of that previous block at which the attacker bytes will be placed initially.
    let attack_ofst = ecb_oracle.find_attack_offset(block_size);
    // Amount with which to fill the first block, so that in the next block we have a known plaintext
    let fill_size = block_size - attack_ofst;
    assert_eq!(random_hdr_size + fill_size, next_block_start_ndx);

    // All the possible ciphertexts, given decreasing padding provided by attacker bytes.
    let all_ct_dec_pads = ecb_oracle.generate_all_ciphertexts(block_size);

    // The obtained plaintext will be appended here.
    // The random header padding and the attacker-controlled known plaintext bytes must be removed.
    // Don't know the length of bytes in the sequence, so the requested capacity is arbitrary.
    let mut plaintext_byte_seq = Vec::with_capacity(2 * block_size);
    let one_short_block_size = block_size - 1;
    // Add head padding so that a sliding window can be formed over the first (block_size - 1) bytes.
    plaintext_byte_seq.resize(one_short_block_size, 'i' as u8);
    // Iterating through different offsets in the plaintext sequence of bytes,
    // generating a (block_size - 1)-sized sliding window.
    for ofst in 0..payload_size {
        let maybe_one_short_chunk = plaintext_byte_seq.get(ofst..ofst + one_short_block_size);
        if let Some(one_short_chunk) = maybe_one_short_chunk {
            assert_eq!(one_short_chunk.len(), one_short_block_size);
            // println!("One short chunk: {one_short_chunk:02x?}");

            let ct_to_pt_blocks = ecb_oracle.possible_ct_to_pt_blocks(one_short_chunk, block_size);
            // println!("{ct_to_pt_blocks:#02x?}, len: {}", ct_to_pt_blocks.len());

            let ct_ndx = ofst % block_size;
            let ct = &all_ct_dec_pads[ct_ndx];
            let rel_block_ndx = ofst / block_size;
            let rel_block_start_byte_ndx = rel_block_ndx * block_size;
            let block_start_ndx = next_block_start_ndx + rel_block_start_byte_ndx;
            // println!("Offset: {ofst}, Block index: {rel_block_ndx}, Ciphertext index = {ct_ndx}");
            let ct_block = &ct[block_start_ndx..][..block_size];
            // println!("ct_block: {ct_block:02x?}");
            let pt_block = ct_to_pt_blocks
                .get(ct_block)
                .expect("There was no mapping for the given ciphertext block.");
            let last_byte = pt_block[one_short_block_size];
            // println!("Last byte: 0x{last_byte:02x} ({:?})", last_byte as char);
            plaintext_byte_seq.push(last_byte);
        } else {
            break;
        }
    }

    let payload_bytes = plaintext_byte_seq[one_short_block_size..].to_vec();
    // The bytes are expected to form a valid string.
    let payload_string = String::from_utf8(payload_bytes).unwrap();
    println!("> Payload:\n{payload_string}");
}
