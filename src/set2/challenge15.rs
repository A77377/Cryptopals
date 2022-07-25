use super::challenge9;

pub fn has_valid_pkcs7_padding(plaintext: &[u8]) -> bool {
    let last_byte = plaintext.last();
    if let Some(&pad_len) = last_byte {
        let pad_start_ndx = plaintext.len() - pad_len as usize;
        plaintext[pad_start_ndx..].iter().all(|&b| b == pad_len)
    } else {
        false
    }
}

pub fn validate_and_strip_pkcs7_padding(padded_plaintext: &[u8]) -> &[u8] {
    if has_valid_pkcs7_padding(padded_plaintext) {
        challenge9::strip_pkcs_no7_padding(padded_plaintext)
    } else {
        panic!("PKCS7 padding of the given plaintext is invalid.")
    }
}
