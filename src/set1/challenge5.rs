pub fn repeating_key_xor(text: &str, key: &str) -> Vec<u8> {
    // Creates an iterator that cycles repeatedly through the key, as desired.
    let key_iter = key.chars().cycle();

    let ciphertext = text
        .as_bytes()
        .iter()
        .zip(key_iter.map(|c| c as u8))
        .map(|(text_byte, key_byte)| *text_byte ^ key_byte)
        .collect::<Vec<u8>>();

    ciphertext
}

pub fn repeating_key_xor_bytes(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    // Creates an iterator that cycles repeatedly through the key, as desired.
    let key_iter = key.iter().cycle();

    let ciphertext = bytes
        .iter()
        .zip(key_iter)
        .map(|(text_byte, key_byte)| *text_byte ^ key_byte)
        .collect::<Vec<u8>>();

    ciphertext
}
