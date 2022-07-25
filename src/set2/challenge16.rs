use std::{collections::BTreeMap, error::Error};

use yansi::Paint;

use super::challenge10;

#[derive(Debug)]
pub struct CBCOracle {
    pub random_key: [u8; 16],
    pub random_iv: [u8; 16],
}

impl CBCOracle {
    pub fn new() -> Self {
        Self {
            random_key: rand::random(),
            random_iv: rand::random(),
        }
    }

    pub fn enc_aes_cbc(&self, plaintext: &[u8]) -> Vec<u8> {
        challenge10::enc_aes_cbc(&self.random_key, &self.random_iv, plaintext)
    }

    pub fn dec_aes_cbc(&self, ciphertext: &[u8]) -> Vec<u8> {
        challenge10::dec_aes_cbc(&self.random_key, &self.random_iv, ciphertext)
    }

    pub fn sanitize_extend_and_encrypt(&self, supplied_str: &str) -> Vec<u8> {
        let plaintext_str = sanitize_and_extend_supplied_str(supplied_str);
        // The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.
        let ciphertext = self.enc_aes_cbc(plaintext_str.as_bytes());
        ciphertext
    }

    // The second function should decrypt the string and look for the characters
    // ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert
    // each resulting string into 2-tuples, and look for the "admin" tuple).
    pub fn decrypt_and_check(&self, ciphertext: &[u8]) -> (Vec<u8>, bool) {
        let plaintext = self.dec_aes_cbc(ciphertext);
        let needle = ";admin=true;".as_bytes();
        let found_needle = plaintext.windows(needle.len()).any(|w| w == needle);
        (plaintext, found_needle)
    }

    pub fn find_block_size(&self) -> Option<usize> {
        let mut block_size = None;
        let mut pt_str = String::new();
        let prev_ct_size = self.sanitize_extend_and_encrypt(&pt_str).len();
        for _ in 1.. {
            pt_str.push('i');
            let cur_ct_size = self.sanitize_extend_and_encrypt(&pt_str).len();
            if cur_ct_size != prev_ct_size {
                block_size = Some(cur_ct_size - prev_ct_size);
                break;
            }
        }
        block_size
    }

    // The same as in challenge 14.
    pub fn find_target_block_start(&self) -> usize {
        // ab - attacker bytes
        let empty_ab_ct = self.sanitize_extend_and_encrypt("");
        let one_ab_ct = self.sanitize_extend_and_encrypt("i");
        let opt_ct_byte = empty_ab_ct
            .into_iter()
            .zip(one_ab_ct.into_iter())
            .enumerate()
            .skip_while(|(_, (e_ct_b, o_ct_b))| e_ct_b == o_ct_b)
            .next();
        let (target_block_start_ndx, _) = opt_ct_byte.unwrap();
        target_block_start_ndx
    }

    pub fn find_attack_offset(&self, block_size: usize) -> usize {
        let mut attacker_string = String::with_capacity(block_size);
        let target_block_start_ndx = self.find_target_block_start();
        let mut prev_target_block = self.sanitize_extend_and_encrypt(&attacker_string)
            [target_block_start_ndx..][..block_size]
            .to_owned();
        let mut atck_ofst = 0;

        for o in 1..=(block_size + 1) {
            attacker_string.push('i');
            let cur_target_block = self.sanitize_extend_and_encrypt(&attacker_string)
                [target_block_start_ndx..][..block_size]
                .to_owned();
            if cur_target_block == prev_target_block {
                atck_ofst = block_size - (o - 1);
                break;
            }
            prev_target_block = cur_target_block;
        }

        atck_ofst
    }
}

pub fn cbc_bitflipping_attack() {
    let cbc_oracle = CBCOracle::new();
    let ct = cbc_oracle.sanitize_extend_and_encrypt(";admin=true");
    let (_, check) = cbc_oracle.decrypt_and_check(&ct);
    assert_eq!(check, false);

    // Determine the attack targets
    let block_size = cbc_oracle.find_block_size().unwrap();
    let target_block_start_ndx = cbc_oracle.find_target_block_start();
    let target_block_ndx = target_block_start_ndx / block_size;
    let attack_offset = cbc_oracle.find_attack_offset(block_size);
    println!(
        "{} {}{}{} {}",
        Paint::red("Attacking block"),
        Paint::yellow("#"),
        Paint::yellow(target_block_ndx),
        Paint::red(", starting at index"),
        Paint::yellow(target_block_start_ndx),
    );
    println!(
        "{} {} {} {} {} {}",
        Paint::blue("Attack offsets:"),
        Paint::green("Global"),
        Paint::yellow(target_block_start_ndx + attack_offset),
        Paint::blue("|"),
        Paint::green("Local"),
        Paint::yellow(attack_offset),
    );

    let mut attack_ct = cbc_oracle.sanitize_extend_and_encrypt(":admin:true");
    let (_, check) = cbc_oracle.decrypt_and_check(&ct);
    assert_eq!(check, false);

    // Flip the necessary bits in the ciphertext
    // Attack the previous ciphertext block to affect the next plaintext block during the XOR
    let mut fst = attack_ct[target_block_start_ndx + attack_offset - block_size];
    let mut snd = attack_ct[target_block_start_ndx + attack_offset - block_size + 6];
    println!("First {fst:02x}, Second {snd:02x}");
    // ':' - 0x3a | ';' - 0x3b | '=' - 0x3d
    attack_ct[target_block_start_ndx + attack_offset - block_size] ^= 1;
    attack_ct[target_block_start_ndx + attack_offset - block_size + 6] ^= 7;
    fst = attack_ct[target_block_start_ndx + attack_offset - block_size];
    snd = attack_ct[target_block_start_ndx + attack_offset - block_size + 6];
    println!("First {fst:02x}, Second {snd:02x}");

    let (pwned_pt, check) = cbc_oracle.decrypt_and_check(&attack_ct);
    assert_eq!(check, true);
    for b in pwned_pt {
        // TODO It almost always is going to work. I should test something different.
        if let Ok(c) = char::try_from(b) {
            print!("{c}");
        } else {
            print!("%{b:02x}")
        }
    }
    println!();
}

pub fn quote_special_chars_bytes(supplied_str: &str) -> Vec<u8> {
    let mut escaped_bytes = Vec::new();
    // From https://doc.rust-lang.org/std/primitive.char.html#method.encode_utf8
    // A buffer of length four is large enough to encode any char.
    let mut char_bytes = [0; 4];
    for c in supplied_str.chars() {
        match c {
            ';' | '=' => {
                escaped_bytes.push('%' as u8);
                escaped_bytes.extend(format!("{:02x}", c as u8).into_bytes());
            }
            // The str returned by encode_utf8() disregards other bytes in the
            // `char_bytes` buffer, using the appropriate subslice.
            _ => escaped_bytes.extend_from_slice(c.encode_utf8(&mut char_bytes).as_bytes()),
        }
    }
    escaped_bytes
}

pub fn quote_special_chars(supplied_str: &str) -> String {
    let mut escaped_chars = String::new();
    supplied_str.chars().for_each(|c| match c {
        ';' | '=' => {
            escaped_chars.push('%');
            // If using UTF-8 chars that use more than one byte, instead of casting to u8, use
            // c.encode_utf8(&mut char_bytes).as_bytes() and the necessary char_bytes buffers.
            escaped_chars.push_str(&format!("{:02x}", c as u8));
        }
        _ => escaped_chars.push(c),
    });
    escaped_chars
}

pub fn sanitize_and_extend_supplied_str(supplied_str: &str) -> String {
    // The first function should take an arbitrary input string, prepend the string:
    let prepend_str = "comment1=cooking%20MCs;userdata=";
    // The function should quote out the ";" and "=" characters.
    let sanitized_user_str = quote_special_chars(supplied_str);
    // .. and append the string:
    let append_str = ";comment2=%20like%20a%20pound%20of%20bacon";
    // Build plaintext string
    let mut plaintext_str =
        String::with_capacity(prepend_str.len() + sanitized_user_str.len() + append_str.len());
    plaintext_str.push_str(prepend_str);
    plaintext_str.push_str(&sanitized_user_str);
    plaintext_str.push_str(append_str);

    plaintext_str
}
