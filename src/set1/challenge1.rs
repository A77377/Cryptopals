use std::result::Result;
// use anyhow::Result;
use std::error::Error;

// Rule: Always operate on raw bytes, never on encoded strings.
//       Only use hex and base64 for pretty-printing.
pub fn hex_to_base64(hex_str: &str) -> Result<String, Box<dyn Error>> {
    let bytes = hex_to_bytes(hex_str)?;
    bytes_to_base64(&bytes)
}

// Normally, hex_to_bytes would return just enough bytes in its return Vec.
// No longer true: However, to avoid reallocations, the Vec is sized to align at a Base64 boundary.
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    // No longer true: Aligned to u8 and Base64 boundaries.
    let hex_char_count = hex_str.chars().count();
    let bytes_len = bytes_len(hex_char_count);
    let mut bytes = Vec::with_capacity(bytes_len);

    // Requires new allocation. Not perfect.
    // let collected_string;
    // let mut hex_chars = if hex_char_count.rem(2) == 0 {
    //     hex_str.chars()
    // } else {
    //     collected_string = ["0", hex_str]
    //         .iter()
    //         .flat_map(|s| s.chars())
    //         .collect::<String>();
    //     collected_string.chars()
    // };

    // Iterate over the &str, take every 2 chars, generate the byte and collect
    let mut hex_chars = hex_str.chars();
    let mut fst = if (hex_char_count % 2) != 0 {
        Some('0')
    } else {
        hex_chars.next()
    };
    while fst != None {
        let snd = hex_chars.next();
        let byte_val = hex_byte_val(fst.unwrap_or('0'), snd.unwrap_or('0'))?;
        bytes.push(byte_val);
        fst = hex_chars.next();
    }

    // No longer used: Used to pad the vector with 0s for alignment with Base64 boundaries
    // let cap = bytes.capacity();
    // bytes.resize(cap, 0);

    Ok(bytes)
}

pub fn bytes_to_base64(bytes: &[u8]) -> Result<String, Box<dyn Error>> {
    let mut bytes_iter = bytes.iter();
    let bytes_len = bytes.len();
    let mut base64_str = String::with_capacity((align(bytes_len, 3) * 4) / 3);
    let padding_char = '=';
    let mut i = 0;

    while i < bytes_len {
        let fst = bytes_iter.next();
        let snd = bytes_iter.next();
        let trd = bytes_iter.next();
        let (fst_char, snd_char, trd_char, fth_char) = if let Some(fst_byte) = fst {
            let fst_char = byte_to_base64_char(fst_byte >> 2)?;
            if let Some(snd_byte) = snd {
                let snd_char = byte_to_base64_char((fst_byte << 4 | snd_byte >> 4) & (1 << 6) - 1)?;
                if let Some(trd_byte) = trd {
                    let trd_char =
                        byte_to_base64_char((snd_byte << 2 | trd_byte >> 6) & (1 << 6) - 1)?;
                    let fth_char = byte_to_base64_char(trd_byte & (1 << 6) - 1)?;
                    // Also applies to initial sequences of bytes.
                    // Final quantum of encoding input is an integral multiple of 24 bits.
                    // The final unit of encoded output will be an integral multiple of 4 characters
                    // with no "=" padding.
                    (fst_char, snd_char, trd_char, fth_char)
                } else {
                    // Final quantum of encoding input is exactly 16 bits
                    // The final unit of encoded output will be 3 characters
                    // followed by one "=" padding character.
                    let trd_byte = 0;
                    let trd_char =
                        byte_to_base64_char((snd_byte << 2 | trd_byte >> 6) & (1 << 6) - 1)?;
                    (fst_char, snd_char, trd_char, padding_char)
                }
            } else {
                // Final quantum of encoding is exactly 8 bits.
                // The final unit of encoded output will be 2 characters
                // followed by two "=" padding characters.
                let snd_byte = 0;
                let snd_char = byte_to_base64_char((fst_byte << 4 | snd_byte >> 4) & (1 << 6) - 1)?;
                (fst_char, snd_char, padding_char, padding_char)
            }
        } else {
            unreachable!()
        };

        base64_str.push(fst_char);
        base64_str.push(snd_char);
        base64_str.push(trd_char);
        base64_str.push(fth_char);
        i += 3;
    }

    Ok(base64_str)
}

fn bytes_len(hex_str_len: usize) -> usize {
    // The number of bits in the Vec<u8> must be a multiple of 4, 8 and 6, in order to
    // guarantee a match between the hexadecimal and Base64 representations.
    // It must be a multiple of 4 so that the sequence of bits can be represented as nibbles (4 bits).
    // Since the vector is made of 8-bit unsigned integers, this is automatically guaranteed.
    // The same guarantee exists for the requirement of being a multiple of 8.
    // It must also be a multiple of 6 because every Base64 char corresponds to 6 bits and this way
    // we have a 1-to-1 matching, as we have for the hex chars.

    // Since each hexadecimal nibble char corresponds to 4-bits, the corresponding Vec<u8> should
    // have at least enough bytes for the hex chars.
    align(hex_str_len, 2) / 2
    // let bytes_len = align(hex_str_len, 2) / 2;
    // The least common multiple of the values is 24 (= 3 x 8), which means that the resulting
    // Vec<u8> must have a length that is a multiple of 3.
    // For exact alignment between hex and Base64 values.
    // align(bytes_len, 3)
}

pub fn align(value: usize, alignment: usize) -> usize {
    let remainder = value % alignment;
    if remainder == 0 {
        value
    } else {
        value + (alignment - remainder)
    }
}

/// Converts successfully only valid lowercase nibble chars.
pub fn hex_byte_val(high_nibble: char, low_nibble: char) -> Result<u8, Box<dyn Error>> {
    let high_nibble = hex_nibble_val(high_nibble)?;
    let low_nibble = hex_nibble_val(low_nibble)?;
    Ok((high_nibble << 4) | low_nibble)
}

/// Converts successfully only valid lowercase nibble chars.
pub fn hex_nibble_val(hex_char: char) -> Result<u8, Box<dyn Error>> {
    match hex_char {
        '0' => Ok(0x0),
        '1' => Ok(0x1),
        '2' => Ok(0x2),
        '3' => Ok(0x3),
        '4' => Ok(0x4),
        '5' => Ok(0x5),
        '6' => Ok(0x6),
        '7' => Ok(0x7),
        '8' => Ok(0x8),
        '9' => Ok(0x9),
        'a' => Ok(0xa),
        'b' => Ok(0xb),
        'c' => Ok(0xc),
        'd' => Ok(0xd),
        'e' => Ok(0xe),
        'f' => Ok(0xf),
        _ => Err(From::from(
            "Invalid hexadecimal character. Must be lowercase.",
        )),
    }
}

fn byte_to_base64_char(byte: u8) -> Result<char, Box<dyn Error>> {
    match byte {
        0b000000 => Ok('A'),
        0b000001 => Ok('B'),
        0b000010 => Ok('C'),
        0b000011 => Ok('D'),
        0b000100 => Ok('E'),
        0b000101 => Ok('F'),
        0b000110 => Ok('G'),
        0b000111 => Ok('H'),
        0b001000 => Ok('I'),
        0b001001 => Ok('J'),
        0b001010 => Ok('K'),
        0b001011 => Ok('L'),
        0b001100 => Ok('M'),
        0b001101 => Ok('N'),
        0b001110 => Ok('O'),
        0b001111 => Ok('P'),
        0b010000 => Ok('Q'),
        0b010001 => Ok('R'),
        0b010010 => Ok('S'),
        0b010011 => Ok('T'),
        0b010100 => Ok('U'),
        0b010101 => Ok('V'),
        0b010110 => Ok('W'),
        0b010111 => Ok('X'),
        0b011000 => Ok('Y'),
        0b011001 => Ok('Z'),
        0b011010 => Ok('a'),
        0b011011 => Ok('b'),
        0b011100 => Ok('c'),
        0b011101 => Ok('d'),
        0b011110 => Ok('e'),
        0b011111 => Ok('f'),
        0b100000 => Ok('g'),
        0b100001 => Ok('h'),
        0b100010 => Ok('i'),
        0b100011 => Ok('j'),
        0b100100 => Ok('k'),
        0b100101 => Ok('l'),
        0b100110 => Ok('m'),
        0b100111 => Ok('n'),
        0b101000 => Ok('o'),
        0b101001 => Ok('p'),
        0b101010 => Ok('q'),
        0b101011 => Ok('r'),
        0b101100 => Ok('s'),
        0b101101 => Ok('t'),
        0b101110 => Ok('u'),
        0b101111 => Ok('v'),
        0b110000 => Ok('w'),
        0b110001 => Ok('x'),
        0b110010 => Ok('y'),
        0b110011 => Ok('z'),
        0b110100 => Ok('0'),
        0b110101 => Ok('1'),
        0b110110 => Ok('2'),
        0b110111 => Ok('3'),
        0b111000 => Ok('4'),
        0b111001 => Ok('5'),
        0b111010 => Ok('6'),
        0b111011 => Ok('7'),
        0b111100 => Ok('8'),
        0b111101 => Ok('9'),
        0b111110 => Ok('+'),
        0b111111 => Ok('/'),
        _ => Err(From::from(
            "Invalid byte: the given byte does not produce a Base64 character.",
        )),
    }
}
