use super::challenge1;
// use anyhow::Result;
use std::{error::Error, result::Result};

pub fn fixed_xor(hex_str_a: &str, hex_str_b: &str) -> Result<String, Box<dyn Error>> {
    validate_str_lens(hex_str_a, hex_str_b)?;
    let bytes_a = challenge1::hex_to_bytes(hex_str_a)?;
    dbg!(&bytes_a);
    let bytes_b = challenge1::hex_to_bytes(hex_str_b)?;
    dbg!(&bytes_b);

    let xor_bytes = xor_byte_arrays(bytes_a, bytes_b);
    dbg!(&xor_bytes);
    bytes_to_hex_str(&xor_bytes)
}

fn xor_byte_arrays(bytes_a: Vec<u8>, bytes_b: Vec<u8>) -> Vec<u8> {
    bytes_a
        .into_iter()
        .zip(bytes_b.into_iter())
        .map(|(x, y)| x ^ y)
        .collect()
}

fn validate_str_lens(hex_str_a: &str, hex_str_b: &str) -> Result<(), Box<dyn Error>> {
    if hex_str_a.len() != hex_str_b.len() {
        Err(From::from("The 2 input strings must be of equal length."))
    } else {
        Ok(())
    }
}

fn bytes_to_hex_str(bytes: &[u8]) -> Result<String, Box<dyn Error>> {
    let mut hex_str = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let high = byte >> 4;
        let low = byte & (1 << 4) - 1;
        hex_str.push(byte_to_hex_char(high)?);
        hex_str.push(byte_to_hex_char(low)?);
    }
    Ok(hex_str)

    // let strings = bytes
    //     .iter()
    //     .map(|b| format!("{b:02x}"))
    //     .collect::<Vec<String>>();
    // Ok(strings.concat())
}

fn byte_to_hex_char(byte: u8) -> Result<char, Box<dyn Error>> {
    match byte {
        0x0 => Ok('0'),
        0x1 => Ok('1'),
        0x2 => Ok('2'),
        0x3 => Ok('3'),
        0x4 => Ok('4'),
        0x5 => Ok('5'),
        0x6 => Ok('6'),
        0x7 => Ok('7'),
        0x8 => Ok('8'),
        0x9 => Ok('9'),
        0xa => Ok('a'),
        0xb => Ok('b'),
        0xc => Ok('c'),
        0xd => Ok('d'),
        0xe => Ok('e'),
        0xf => Ok('f'),
        _ => Err(From::from("Invalid byte. Must contain a nibble.")),
    }
}
