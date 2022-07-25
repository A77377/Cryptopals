use std::time::Instant;

use cryptopals::{
    set1::{
        challenge1::{self, bytes_to_base64, hex_to_base64, hex_to_bytes},
        challenge2::fixed_xor,
        challenge3::{eff_single_byte_xor_cipher, single_byte_xor_cipher},
        challenge4::detect_single_char_xor,
        challenge5::repeating_key_xor,
        challenge6::{
            base64_to_bytes, break_repeating_key_xor, count_set_bits, count_set_bits_u8,
            hamming_distance_str, hamming_distance_str_wrapper,
        },
        challenge7::{aes_in_ecb_mode, dec_aes_ecb},
        challenge8::detect_aes_ecb,
    },
    set2::{
        challenge10::cbc_mode,
        challenge11::{
            detect_block_cipher_mode, enc_aes_ecb, encryption_oracle, generate_random_16_bytes,
        },
        challenge12::{self, byte_at_a_time_ecb_dec, ECBOracle},
        challenge13::{get_admin_role, get_block_size, key_val_parsing, Role, User, UserOracle},
        challenge14::{self, RandomHeadECBOracle},
        challenge16::{cbc_bitflipping_attack, quote_special_chars_bytes, CBCOracle},
        challenge9::{append_pkcs_no7_padding, pad_str_to_bs_width},
    },
};

fn main() {
    // println!("Cryptopals");
    // let a = hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
    // let a = hex_to_base64("4d616e").unwrap();
    // println!("{a}");
    // let a = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    // let mut b = r"f49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    // b = r" ";
    // let res = hex_to_bytes(b).unwrap();
    // println!("{a:?}");
    // println!("{b:x?}");
    // println!("{res:02x?} {} {}", res.len(), res.capacity());

    // let a = "ab";
    // let b = "12";
    // let c = fixed_xor(a, b);
    // dbg!(c.unwrap());

    // let now = Instant::now();
    // println!("{}", now.elapsed().as_millis());
    // let hex_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    // // let a = single_byte_xor_cipher(hex_str);
    // dbg!(a);
    // let b = eff_single_byte_xor_cipher(hex_str);
    // dbg!(b);

    // detect_single_char_xor().unwrap();

    // let a = 'a';
    // dbg!(a as u8, b'a');
    // let a = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    // let b = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    // let c = hex_to_bytes(a).unwrap();
    // let d: String = c.iter().map(|b|*b as char).collect();
    // dbg!(b, c, d);
    // let a = '大';
    // dbg!(u8::try_from(a));

    // let pt = "Burning 'em, if you ain't quick and nimble\n\
    //                       I go crazy when I hear a cymbal";
    // let k = "ICE";
    // // repeating_key_xor(pt, k);
    // dbg!(repeating_key_xor(pt, k));

    // dbg!(count_set_bits_u8(7));

    // let a = "geeksforgeeks";
    // let b = "geeksandgeeks";
    // let a = "this is a test";
    // let b = "wokka wokka!!!";
    // dbg!(hamming_distance_str_wrapper(a, b));

    // let b64 = "HUIfTQsPAh9PE048GmllH0kcDk4TAQsHThsBFkU2AB4BSWQgVB0dQzNTTmVS";
    // let hex = "1d421f4d0b0f021f4f134e3c1a69651f491c0e4e13010b074e1b01164536001e01496420541d1d4333534e6552";
    // let hex_bytes = hex_to_bytes(hex).unwrap();
    // let bytes_to_b64 = bytes_to_base64(&hex_bytes).unwrap();
    // dbg!(base64_to_bytes(
    //     "BgBHVBwNRU0HBAxTEjwMHghJGgkRTxRMIRpHKwAFHUdZEQQJAGQmB1MANxYG"
    // ));

    // let bytes = base64_to_bytes(b64).unwrap();
    // let res = bytes_to_base64(&bytes).unwrap();

    // println!("{b64}");
    // println!("{bytes_to_b64}");
    // println!("----");
    // println!("{hex_bytes:x?}");
    // println!("B64");
    // println!("{bytes:x?}");

    // assert_eq!(b64, res);
    // assert_eq!(b64, bytes_to_b64);
    // assert_eq!(hex_bytes, bytes);

    // let (key, pt) = break_repeating_key_xor().unwrap();
    // println!("Key:  {key}");
    // println!("Plaintext:");
    // println!("{pt}");

    // let res = aes_in_ecb_mode().unwrap();
    // println!("{res}");
    // detect_aes_ecb();

    // let msg = "YELLOW SUBMARINE";
    // let mut expected_result = Vec::from(msg);
    // for _ in 0..4 {
    //     expected_result.push(0x4);
    // }
    // println!("{expected_result:02x?}");
    // dbg!(&expected_result.len());

    // let res = pad_str_to_bs_width(msg, 20);
    // println!("{res:02x?}");
    // dbg!(&res.len());
    // cbc_mode();

    // let key = generate_random_16_bytes();
    // println!("Key: {key:02x?}, len: {}", key.len());
    // let mut pt = Vec::with_capacity(16 * 2);
    // pt.extend_from_slice(&generate_random_16_bytes());
    // pt.extend_from_slice(&generate_random_16_bytes());
    // println!("PT: {pt:02x?}, len: {}", pt.len());
    // let ct = enc_aes_ecb(&pt, &key);
    // println!("CT: {ct:02x?}, len: {}", ct.len());
    // let pt_again = dec_aes_ecb(&ct, &key);
    // println!("PT AGAIN: {pt_again:02x?}, len: {}", pt_again.len());
    // assert_eq!(pt, pt_again);
    // let ct_again = enc_aes_ecb(&pt_again, &key);
    // println!("CT AGAIN: {ct_again:02x?}, len: {}", ct_again.len());
    // assert_eq!(ct, ct_again);

    // detect_block_cipher_mode();

    // let mut a = vec![1, 2, 3, 4, 5];
    // // a.insert(3, 28);
    // a[3] = 28;
    // println!("{a:?}");
    // let mut b = Vec::with_capacity(6);
    // b.extend_from_slice(&a);
    // dbg!(a.capacity(), b.capacity());
    // println!("{:?}", &b[..]);
    // b[1..3].fill(44);
    // println!("{:?}", &b[..]);

    // let upper_bound = 33;
    // let mut pt_bytes = Vec::<u8>::with_capacity(upper_bound);
    // for test_block_size in 1..upper_bound {
    //     unsafe {
    //         pt_bytes.set_len(test_block_size);
    //     }
    //     pt_bytes[test_block_size - 1] = 'A' as u8;
    //     println!("{:?}", &pt_bytes[..]);
    // }

    // let ecb_o = ECBOracle::new();
    // let bs = ecb_o.find_block_size().unwrap_or(0);
    // println!("Block size: {bs}");
    // let a: &[i32] = &[1, 2, 3, 4];
    // let b = &[1, 2, 3, 4];
    // assert_eq!(a[..], b[..]);

    // byte_at_a_time_ecb_dec();
    // let test_pkcs7 = enc_aes_ecb(&[], &[0; 16]);
    // println!("Enc: {test_pkcs7:02x?}");
    // let pkcs7pad = pkcs_no7_padding(&[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], 16);
    // println!("Padded Bytes: {pkcs7pad:02x?}");
    // println!(
    //     "Stripped Bytes: {:02x?}",
    //     &pkcs_no7_strip_padding(&pkcs7pad)
    // );

    // byte_at_a_time_ecb_dec();

    // let res = encryption_oracle(&key);
    // println!("Padded Bytes: {res:02x?}");

    // let test_kv_parse = "foo=bar&baz=qux&zap=zazzle";
    // let maps = key_val_parsing(test_kv_parse);
    // println!("{maps:#?}");
    // println!("{}", Role::User.to_string());
    // let u = User::profile_for("foo@bar.com");
    // println!("{u}");
    // let u_string = u.to_string();
    // assert_eq!(u_string, "email=foo@bar.com&uid=10&role=user");

    // let uo = UserOracle::new();
    // let user = User::profile_for("foo@bar.com");
    // let enc_u = uo.encrypt_user(&user);
    // let dec_u = uo.decrypt_user(&enc_u);
    // let u_str = String::from_utf8(dec_u).unwrap();
    // let u_map = key_val_parsing(&u_str);
    // println!("{u_str}");
    // println!("{u_map:#?}");

    // let bs = get_block_size().unwrap();
    // println!("Block size: {bs}");

    // get_admin_role();

    // let admin_str = "email=iiii@pwned.eu&uid=10&role=admin";
    // let (fst_block, rest) = admin_str.split_at(16);
    // println!("1.{fst_block:?} rest.{rest:?}");
    // let (snd_block, rest) = rest.split_at(16);
    // println!("2.{snd_block:?} rest.{rest:?}");

    // let rh_ecb_oracle = RandomHeadECBOracle::new();
    // let rh_block_size = rh_ecb_oracle.find_block_size().unwrap();
    // println!("Random Head Padding Oracle Block Size: {rh_block_size}");
    // let changing_block_start_ndx = rh_ecb_oracle.find_target_block_start();
    // println!("Changing block start index: {changing_block_start_ndx}");
    // let attack_offset = rh_ecb_oracle.find_attack_offset(rh_block_size);
    // println!("Attacker bytes offset: {attack_offset}");
    // let header_size = rh_ecb_oracle.find_random_header_size(rh_block_size);
    // println!("Header size: {header_size}");
    // let payload_size = rh_ecb_oracle.find_payload_size(rh_block_size);
    // println!("Payload size: {payload_size}");
    // let is_ecb = rh_ecb_oracle.detect_oracle_aes_ecb(rh_block_size);
    // println!("Is ECB?: {is_ecb}");
    // challenge14::byte_at_a_time_ecb_dec();

    let a = CBCOracle::new();
    let b = CBCOracle::new();
    // let c = CBCOracle::new();
    println!("{a:?}");
    println!("{b:?}");
    // println!("{c:?}");
    let atbs = a.find_target_block_start();
    let btbs = b.find_target_block_start();
    println!("A -> {atbs} B -> {btbs}");
    let abs = a.find_block_size().unwrap();
    println!("Block size of A: {abs}");
    let aao = a.find_attack_offset(abs);
    println!("Attack offset of A: {aao}");

    println!("{:02x}", '@' as u8);
    let s = ";admin=true;=;=;";
    let eb = quote_special_chars_bytes(s);
    let es = String::from_utf8(eb).unwrap();
    println!("Escaped string: {es:?}");

    let multibyte = '🍪';
    let mut char_bytes = [0; 4];
    multibyte.encode_utf8(&mut char_bytes);
    println!("{multibyte}: {char_bytes:02x?}");
    let singlebyte = '=';
    let curious = singlebyte.encode_utf8(&mut char_bytes);
    println!("{curious} {:02x?}", curious.as_bytes());
    println!("{singlebyte}: {char_bytes:02x?}");

    cbc_bitflipping_attack();
}

// static a: &[i32] = &[1, 2, 3];
