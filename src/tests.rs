use std::fs;

use crate::set1::challenge6;
use crate::set1::{
    challenge1::hex_to_bytes, challenge5::repeating_key_xor,
    challenge6::hamming_distance_str_wrapper,
};
use crate::set2::challenge10;
use crate::set2::challenge12::byte_at_a_time_ecb_dec;
use crate::set2::challenge15::has_valid_pkcs7_padding;
use crate::set2::challenge9::{pad_str_to_bs_width, strip_pkcs_no7_padding};

use super::*;

#[test]
fn set1_challenge1() {
    let test_hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let test_base64_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let res_base64_str = set1::challenge1::hex_to_base64(test_hex_str).unwrap();

    assert_eq!(res_base64_str, test_base64_str);
}

#[test]
fn set1_challenge2() {
    let test_hex_str_a = "1c0111001f010100061a024b53535009181c";
    let test_hex_str_b = "686974207468652062756c6c277320657965";
    let test_fixed_xor = "746865206b696420646f6e277420706c6179";

    let res_fixed_xor = set1::challenge2::fixed_xor(test_hex_str_a, test_hex_str_b).unwrap();

    assert_eq!(res_fixed_xor, test_fixed_xor);
}

#[test]
fn set1_challenge3() {
    let test_hex_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let res_single_byte_xor_cipher =
        set1::challenge3::single_byte_xor_cipher(test_hex_str).unwrap();
    assert_eq!(res_single_byte_xor_cipher, 'X');
    assert_eq!(
        set1::challenge3::eff_single_byte_xor_cipher(test_hex_str)
            .unwrap()
            .0,
        'X'
    );
}

#[test]
fn set1_challenge5() {
    let plaintext = "Burning 'em, if you ain't quick and nimble\n\
                          I go crazy when I hear a cymbal";
    let key = "ICE";
    let ciphertext = repeating_key_xor(plaintext, key);
    let test_res_hex_str = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    let test_res_bytes = hex_to_bytes(test_res_hex_str)
        .expect("The expected result could not be converted to bytes.");
    assert_eq!(ciphertext, test_res_bytes)
}

#[test]
fn set1_challenge6() {
    let hd_str_a = "this is a test";
    let hd_str_b = "wokka wokka!!!";
    assert_eq!(hamming_distance_str_wrapper(hd_str_a, hd_str_b), 37);
}

#[test]
fn set2_challenge9() {
    let initial_block_str = "YELLOW SUBMARINE";
    let mut expected_padded_result = Vec::from(initial_block_str);
    for _ in 0..4 {
        expected_padded_result.push(0x4);
    }
    let expected_stripped_result = strip_pkcs_no7_padding(&expected_padded_result).to_vec();
    assert_eq!(
        pad_str_to_bs_width(initial_block_str, 20),
        expected_padded_result
    );
    assert_eq!(
        initial_block_str,
        String::from_utf8(expected_stripped_result).unwrap()
    )
}

#[test]
fn set2_challenge10() {
    let key_bytes = "YELLOW SUBMARINE".as_bytes();
    let iv = [0_u8; 16];
    let ciphertext_str = fs::read_to_string("data/10.txt").unwrap();
    let ciphertext_bytes = challenge6::base64_to_bytes(&ciphertext_str.replace("\n", "")).unwrap();
    let plaintext_bytes = challenge10::dec_aes_cbc(key_bytes, &iv, &ciphertext_bytes);
    let repeat_ciphertext_bytes = challenge10::enc_aes_cbc(key_bytes, &iv, &plaintext_bytes);
    let repeat_plaintext_bytes = challenge10::dec_aes_cbc(key_bytes, &iv, &repeat_ciphertext_bytes);
    assert_eq!(ciphertext_bytes, repeat_ciphertext_bytes);
    assert_eq!(plaintext_bytes, repeat_plaintext_bytes);
}

#[test]
fn set2_challenge12() {
    let expected_res = "Rollin' in my 5.0\n\
                              With my rag-top down so my hair can blow\n\
                              The girlies on standby waving just to say hi\n\
                              Did you stop? No, I just drove by\n";
    let res = byte_at_a_time_ecb_dec();
    assert_eq!(expected_res, res);
}

#[test]
fn set2_challenge15() {
    let input_hex = "494345204943452042414259";
    let input_bytes = hex_to_bytes(input_hex).unwrap();
    let valid_pkcs7_padding = [0x04, 0x04, 0x04, 0x04];
    let invalid_pkcs7_padding_1 = [0x05, 0x05, 0x05, 0x05];
    let mut valid_input = input_bytes.clone();
    valid_input.extend_from_slice(&valid_pkcs7_padding);
    assert!(has_valid_pkcs7_padding(&valid_input));
    let mut invalid_input_1 = input_bytes.clone();
    invalid_input_1.extend_from_slice(&invalid_pkcs7_padding_1);
    assert!(!has_valid_pkcs7_padding(&invalid_input_1));
    let invalid_pkcs7_padding_2 = [0x01, 0x02, 0x03, 0x04];
    let mut invalid_input_2 = input_bytes.clone();
    invalid_input_2.extend_from_slice(&invalid_pkcs7_padding_2);
    assert!(!has_valid_pkcs7_padding(&invalid_input_2));
}
