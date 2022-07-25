use std::{collections::BTreeMap, fmt::Display};

use crate::{
    set1::{challenge1, challenge7},
    set2::{challenge11, challenge9},
};

pub fn key_val_parsing(input: &str) -> BTreeMap<&str, &str> {
    let mut mappings = BTreeMap::new();
    let str_splits = input.split('&');
    for str_split in str_splits {
        let mut kv_pair = str_split.split('=');
        // I unwrap() because I expect to there always be a key-value pair.
        mappings.insert(kv_pair.next().unwrap(), kv_pair.next().unwrap());
    }
    mappings
}

pub struct UserOracle {
    aes_ecb_key: Vec<u8>,
}

const BLOCK_SIZE: usize = 16;

impl UserOracle {
    pub fn new() -> Self {
        let random_key: [u8; BLOCK_SIZE] = rand::random();
        Self {
            aes_ecb_key: random_key.to_vec(),
        }
    }

    pub fn encrypt_user(&self, user: &User) -> Vec<u8> {
        let user_as_string = user.to_string();
        let user_as_bytes = user_as_string.as_bytes();
        challenge11::enc_aes_ecb(user_as_bytes, &self.aes_ecb_key)
    }

    pub fn decrypt_user(&self, ciphertext: &[u8]) -> Vec<u8> {
        challenge7::dec_aes_ecb(ciphertext, &self.aes_ecb_key)
    }
}

pub struct User {
    email: String,
    uid: u64,
    // role: Role,
    role: String,
}

pub enum Role {
    User,
}

impl Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let role_as_str = match &self {
            Role::User => "user",
        };
        write!(f, "{role_as_str}")
    }
}

impl User {
    pub fn profile_for(email: &str) -> Self {
        let safe_email = email.replace(['&', '"'], "");
        User {
            email: safe_email,
            // uid: rand::random(),
            uid: 10,
            // role: Role::User,
            role: "user".to_owned(),
        }
    }
}

impl Display for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let email = &self.email;
        let uid = self.uid;
        // let role = self.role.to_string();
        let role = &self.role;
        write!(f, "email={email}&uid={uid}&role={role}")
    }
}

// The strategy to create an admin could probably try to isolate
// the value of the role key in a block.
// A block with the value 'admin' and remaining padding could be crafted
// and encripted.
// The way to position the role value at the right location would be to
// give an input email of the right size.
// The problem is that we don't know the key. Maybe the oracle keeps the
// same random key for as long as it exists?
// Then we could try to input "admin" + (padding until block bound) and
// obtain the needed block of ciphertext.
// Don't know if I can do this in Rust, where str is made of contiguous
// valid UTF-8 bytes.

pub fn get_block_size() -> Option<usize> {
    let mut block_size = None;
    let mut email = String::new();
    let uo = UserOracle::new();
    let mut user = User::profile_for(&email);
    let mut prev_ct_size = uo.encrypt_user(&user).len();
    // println!("First CT size: {prev_ct_size}");
    for _ in 1.. {
        email.push('i');
        user = User::profile_for(&email);
        let cur_ct = uo.encrypt_user(&user);
        let cur_ct_size = cur_ct.len();
        // println!("CT size for size {s}: {cur_ct_size}");
        if cur_ct_size != prev_ct_size {
            block_size = Some(cur_ct_size - prev_ct_size);
            break;
        }
        prev_ct_size = cur_ct_size;
    }

    block_size
}

pub fn get_admin_role() {
    let block_size = get_block_size().unwrap();
    println!("Block size: {block_size}");
    let part_target_str = "@pwned.eu&uid=10&role=";
    let email_key_str = "email=";
    let part_target_str_size = part_target_str.as_bytes().len();
    println!("Part of target str byte size: {part_target_str_size}");
    let email_key_str_size = email_key_str.as_bytes().len();
    println!("Email key byte size: {email_key_str_size}");
    let bytes_to_bs_bound = challenge1::align(part_target_str_size, block_size)
        - (email_key_str_size + part_target_str_size);
    println!("Bytes to block-sized boundary: {bytes_to_bs_bound}");
    assert_eq!('i'.len_utf8(), 1);
    let local_part = "i".repeat(bytes_to_bs_bound);
    let local_part_size = local_part.as_bytes().len();
    println!("Local-part size: {local_part_size}");
    let target_str = format!("{email_key_str}{local_part}{part_target_str}");
    println!("Target string: {target_str}");
    let target_str_size = target_str.as_bytes().len();
    println!("Target string size: {target_str_size}");
    let uo = UserOracle::new();
    let target_user = User::profile_for(&format!("{local_part}@pwned.eu"));
    let mut ct_patch_target = uo.encrypt_user(&target_user);

    let admin_str = "admin";
    let admin_email_val_head_pad_size = block_size - email_key_str_size;
    let admin_email_val_head_pad = "i".repeat(admin_email_val_head_pad_size);
    let pkcs7_padded_admin_block =
        challenge9::append_pkcs_no7_padding(admin_str.as_bytes(), block_size);
    let padded_admin_block_str = unsafe {
        let pkcs7_padded_admin_block_str = String::from_utf8_unchecked(pkcs7_padded_admin_block);
        format!("{admin_email_val_head_pad}{pkcs7_padded_admin_block_str}")
    };
    println!("Padded admin block string: {padded_admin_block_str}");
    let admin_block_user = User::profile_for(&padded_admin_block_str);
    println!("Admin block user: {admin_block_user}");
    let ct_admin_patch_block = uo.encrypt_user(&admin_block_user);
    assert_eq!(
        email_key_str_size + admin_email_val_head_pad_size,
        block_size
    );
    // The patch block with the 'admin' role value should be the second block (index 1) in the
    // ciphertext.
    let admin_patch_block = &ct_admin_patch_block[block_size..][..block_size];
    let block_to_patch = &mut ct_patch_target[target_str_size..][..block_size];
    for (i, &byte) in admin_patch_block.into_iter().enumerate() {
        block_to_patch[i] = byte;
    }
    let admin_bytes = uo.decrypt_user(&ct_patch_target);
    let admin_str = String::from_utf8(admin_bytes).unwrap();
    println!("Admin encoded string: {admin_str}");
    let admin_map = key_val_parsing(&admin_str);
    println!("Admin mappings:\n{admin_map:#?}");
}

// "Before we do the attack, a quick reminder: encryption does not prevent modifications of the message. For authenticity of the message you need a Message Authentication Code or MAC (typically HMAC) or a signature scheme (RSA signing, DSA etc...).
//  Nowadays you have what we call authenticated encryption that combine an encryption scheme and a MAC because combining them yourself is hazardous as well.
//  The take-away is: here we are going to alter the message easily because it's ECB mode, which is terrible; but do not think that you would be safe using CBC or CTR mode: all these modes are for encryption only and are not made to protect the authenticity of the message."
// From: https://cedricvanrompay.gitlab.io/cryptopals/challenges/09-to-13.html
