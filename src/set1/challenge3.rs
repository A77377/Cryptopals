// use anyhow::Ok;
use itertools::Itertools;

use super::challenge1;
use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    result::Result,
};

pub fn single_byte_xor_cipher(hex_str: &str) -> Result<char, Box<dyn Error>> {
    let bytes = challenge1::hex_to_bytes(hex_str)?;
    single_byte_xor_cipher_bytes(&bytes)
}

pub fn single_byte_xor_cipher_bytes(ciphertext_bytes: &[u8]) -> Result<char, Box<dyn Error>> {
    let char_freqs = english_char_frequency();
    let mut plaintexts = HashMap::new();

    let scorer = |plaintext: &String| {
        let uc_pt = plaintext.to_uppercase();
        let mut uc_pt_freqs = HashMap::new();
        let pt_len = uc_pt.len();
        for c in uc_pt.chars() {
            if !uc_pt_freqs.contains_key(&c) {
                let c_freq = uc_pt.match_indices(c).count();
                uc_pt_freqs.insert(c, c_freq as f64 / pt_len as f64);
            }
        }
        uc_pt_freqs
            .iter()
            .map(|(c, f)| (f - char_freqs.get(&c).unwrap_or(&0.)).abs())
            .sum::<f64>()
    };

    for char in 'A'..='z' {
        let xored_bytes = xor_bytes_with_char(&ciphertext_bytes, char as char)?;
        let str = String::from_utf8(xored_bytes)?;
        plaintexts.insert(char as char, str);
    }

    let leading_char = plaintexts
        .into_iter()
        .sorted_by(|(_a, a_string), (_b, b_string)| {
            scorer(a_string)
                .partial_cmp(&scorer(b_string))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .take(1)
        .map(|x| x.0)
        .next();

    leading_char.ok_or(From::from("No decoding character has been selected."))
}

pub fn eff_single_byte_xor_cipher(hex_str: &str) -> Result<(char, f64), Box<dyn Error>> {
    let ciphertext_bytes = challenge1::hex_to_bytes(hex_str)?;
    let ks = eff_single_byte_xor_cipher_bytes(&ciphertext_bytes)?;
    Ok((ks.key as char, ks.score))
}

#[derive(Debug)]
pub struct KeyScore {
    pub key: u8,
    pub score: f64,
}

pub fn eff_single_byte_xor_cipher_bytes(
    ciphertext_bytes: &[u8],
) -> Result<KeyScore, Box<dyn Error>> {
    // println!("{ciphertext_bytes:?}");
    let ascii_freqs = english_ascii_freqs();
    let cipher_bytes_rel_freqs = bytes_rel_freqs(ciphertext_bytes);

    let mut key_scores = Vec::with_capacity((u8::MAX) as usize);

    for candidate_key in u8::MIN..=u8::MAX {
        if candidate_key.is_ascii() {
            let mut score = 0.;
            for (pt_byte, expected_freq) in ascii_freqs.iter() {
                let ct_byte = candidate_key ^ *pt_byte;
                let real_freq = cipher_bytes_rel_freqs.get(&ct_byte).unwrap_or(&0.);
                score += (real_freq - expected_freq).abs();
            }
            key_scores.push(KeyScore {
                key: candidate_key,
                score,
            });
        }
    }

    let possible_key_score = key_scores
        .into_iter()
        .sorted_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .take(1)
        .next()
        .expect("No result was obtained.");

    Ok(possible_key_score)
}

/// Outputs a map with a u8 key (byte) and the its respective relative frequency within the input slice.
pub fn bytes_rel_freqs(bytes: &[u8]) -> BTreeMap<u8, f64> {
    let bytes_len = bytes.len();
    let mut bytes_rel_freqs = BTreeMap::new();

    for byte in bytes.iter() {
        if !bytes_rel_freqs.contains_key(byte) {
            let byte_count = bytecount::count(bytes, *byte);
            // println!("{byte:x} {byte_count}");
            bytes_rel_freqs.insert(*byte, byte_count as f64 / bytes_len as f64);
        }
    }

    bytes_rel_freqs
}

pub fn xor_bytes_with_char(bytes: &[u8], char: char) -> Result<Vec<u8>, Box<dyn Error>> {
    let byte = u8::try_from(char)?;
    Ok(bytes.iter().map(|&b| b ^ byte).collect())
}

fn english_char_frequency() -> BTreeMap<char, f64> {
    let mut english_frequencies: BTreeMap<char, f64> = BTreeMap::new();
    english_frequencies.insert('A', 0.0651738);
    english_frequencies.insert('B', 0.0124248);
    english_frequencies.insert('C', 0.0217339);
    english_frequencies.insert('D', 0.0349835);
    english_frequencies.insert('E', 0.1041442);
    english_frequencies.insert('F', 0.0197881);
    english_frequencies.insert('G', 0.0158610);
    english_frequencies.insert('H', 0.0492888);
    english_frequencies.insert('I', 0.0558094);
    english_frequencies.insert('J', 0.0009033);
    english_frequencies.insert('K', 0.0050529);
    english_frequencies.insert('L', 0.0331490);
    english_frequencies.insert('M', 0.0202124);
    english_frequencies.insert('N', 0.0564513);
    english_frequencies.insert('O', 0.0596302);
    english_frequencies.insert('P', 0.0137645);
    english_frequencies.insert('Q', 0.0008606);
    english_frequencies.insert('R', 0.0497563);
    english_frequencies.insert('S', 0.0515760);
    english_frequencies.insert('T', 0.0729357);
    english_frequencies.insert('U', 0.0225134);
    english_frequencies.insert('V', 0.0082903);
    english_frequencies.insert('W', 0.0171272);
    english_frequencies.insert('X', 0.0013692);
    english_frequencies.insert('Y', 0.0145984);
    english_frequencies.insert('Z', 0.0007836);
    english_frequencies.insert(' ', 0.1918182);
    english_frequencies
}

// From https://opendata.stackexchange.com/a/19792
pub fn english_ascii_freqs() -> BTreeMap<u8, f64> {
    let mut ascii_frequencies = BTreeMap::new();
    ascii_frequencies.insert(32, 0.167564443682168);
    ascii_frequencies.insert(101, 0.08610229517681191);
    ascii_frequencies.insert(116, 0.0632964962389326);
    ascii_frequencies.insert(97, 0.0612553996079051);
    ascii_frequencies.insert(110, 0.05503703643138501);
    ascii_frequencies.insert(105, 0.05480626188138746);
    ascii_frequencies.insert(111, 0.0541904405334676);
    ascii_frequencies.insert(115, 0.0518864979648296);
    ascii_frequencies.insert(114, 0.051525029341199825);
    ascii_frequencies.insert(108, 0.03218192615049607);
    ascii_frequencies.insert(100, 0.03188948073064199);
    ascii_frequencies.insert(104, 0.02619237267611581);
    ascii_frequencies.insert(99, 0.02500268898936656);
    ascii_frequencies.insert(10, 0.019578060965172565);
    ascii_frequencies.insert(117, 0.019247776378510318);
    ascii_frequencies.insert(109, 0.018140172626462205);
    ascii_frequencies.insert(112, 0.017362092874808832);
    ascii_frequencies.insert(102, 0.015750347191785568);
    ascii_frequencies.insert(103, 0.012804659959943725);
    ascii_frequencies.insert(46, 0.011055184780313847);
    ascii_frequencies.insert(121, 0.010893686962847832);
    ascii_frequencies.insert(98, 0.01034644514338097);
    ascii_frequencies.insert(119, 0.009565830104169261);
    ascii_frequencies.insert(44, 0.008634492219614468);
    ascii_frequencies.insert(118, 0.007819143740853554);
    ascii_frequencies.insert(48, 0.005918945715880591);
    ascii_frequencies.insert(107, 0.004945712204424292);
    ascii_frequencies.insert(49, 0.004937789430804492);
    ascii_frequencies.insert(83, 0.0030896915651553373);
    ascii_frequencies.insert(84, 0.0030701064687671904);
    ascii_frequencies.insert(67, 0.002987392712176473);
    ascii_frequencies.insert(50, 0.002756237869045172);
    ascii_frequencies.insert(56, 0.002552781042488694);
    ascii_frequencies.insert(53, 0.0025269211093936652);
    ascii_frequencies.insert(65, 0.0024774830020061096);
    ascii_frequencies.insert(57, 0.002442242504945237);
    ascii_frequencies.insert(120, 0.0023064144740073764);
    ascii_frequencies.insert(51, 0.0021865587546870337);
    ascii_frequencies.insert(73, 0.0020910417959267183);
    ascii_frequencies.insert(45, 0.002076717421222119);
    ascii_frequencies.insert(54, 0.0019199098857390264);
    ascii_frequencies.insert(52, 0.0018385271551164353);
    ascii_frequencies.insert(55, 0.0018243295447897528);
    ascii_frequencies.insert(77, 0.0018134911904778657);
    ascii_frequencies.insert(66, 0.0017387002075069484);
    ascii_frequencies.insert(34, 0.0015754276887500987);
    ascii_frequencies.insert(39, 0.0015078622753204398);
    ascii_frequencies.insert(80, 0.00138908405321239);
    ascii_frequencies.insert(69, 0.0012938206232079082);
    ascii_frequencies.insert(78, 0.0012758834637326799);
    ascii_frequencies.insert(70, 0.001220297284016159);
    ascii_frequencies.insert(82, 0.0011037374385216535);
    ascii_frequencies.insert(68, 0.0010927723198318497);
    ascii_frequencies.insert(85, 0.0010426370083657518);
    ascii_frequencies.insert(113, 0.00100853739070613);
    ascii_frequencies.insert(76, 0.0010044809306127922);
    ascii_frequencies.insert(71, 0.0009310209736100016);
    ascii_frequencies.insert(74, 0.0008814561018445294);
    ascii_frequencies.insert(72, 0.0008752446473266058);
    ascii_frequencies.insert(79, 0.0008210528757671701);
    ascii_frequencies.insert(87, 0.0008048270353938186);
    ascii_frequencies.insert(106, 0.000617596049210692);
    ascii_frequencies.insert(122, 0.0005762708620098124);
    ascii_frequencies.insert(47, 0.000519607185080999);
    ascii_frequencies.insert(60, 0.00044107665296153596);
    ascii_frequencies.insert(62, 0.0004404428310719519);
    ascii_frequencies.insert(75, 0.0003808001912620934);
    ascii_frequencies.insert(41, 0.0003314254660634964);
    ascii_frequencies.insert(40, 0.0003307916441739124);
    ascii_frequencies.insert(86, 0.0002556203680692448);
    ascii_frequencies.insert(89, 0.00025194420110965734);
    ascii_frequencies.insert(58, 0.00012036277683200988);
    ascii_frequencies.insert(81, 0.00010001709417636208);
    ascii_frequencies.insert(90, 8.619977698342993e-05);
    ascii_frequencies.insert(88, 6.572732994986532e-05);
    ascii_frequencies.insert(59, 7.41571610813331e-06);
    ascii_frequencies.insert(63, 4.626899793963519e-06);
    ascii_frequencies.insert(127, 3.1057272589618137e-06);
    ascii_frequencies.insert(94, 2.2183766135441526e-06);
    ascii_frequencies.insert(38, 2.0282300466689395e-06);
    ascii_frequencies.insert(43, 1.5211725350017046e-06);
    ascii_frequencies.insert(91, 6.97204078542448e-07);
    ascii_frequencies.insert(93, 6.338218895840436e-07);
    ascii_frequencies.insert(36, 5.070575116672349e-07);
    ascii_frequencies.insert(33, 5.070575116672349e-07);
    ascii_frequencies.insert(42, 4.436753227088305e-07);
    ascii_frequencies.insert(61, 2.5352875583361743e-07);
    ascii_frequencies.insert(126, 1.9014656687521307e-07);
    ascii_frequencies.insert(95, 1.2676437791680872e-07);
    ascii_frequencies.insert(9, 1.2676437791680872e-07);
    ascii_frequencies.insert(123, 6.338218895840436e-08);
    ascii_frequencies.insert(64, 6.338218895840436e-08);
    ascii_frequencies.insert(5, 6.338218895840436e-08);
    ascii_frequencies.insert(27, 6.338218895840436e-08);
    ascii_frequencies.insert(30, 6.338218895840436e-08);
    ascii_frequencies
}
