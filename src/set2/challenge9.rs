pub fn pad_str_to_bs_width(input_str: &str, blocksize: usize) -> Vec<u8> {
    let input_bytes = input_str.as_bytes();
    append_pkcs_no7_padding(input_bytes, blocksize)
}

/// From https://datatracker.ietf.org/doc/html/rfc2315#section-10.3
/// This padding method is well-defined if and only if k < 256; methods for larger k are an open issue for further study.
pub fn append_pkcs_no7_padding(input: &[u8], block_size: usize) -> Vec<u8> {
    let input_len = input.len();
    // k - (l mod k): k -> block_size, l -> input length
    let trailing_padding_size = block_size - (input_len % block_size);

    let padded_bytes_len = input_len + trailing_padding_size;

    let mut padded_bytes = Vec::with_capacity(padded_bytes_len);
    padded_bytes.extend_from_slice(input);
    padded_bytes.resize(padded_bytes_len, trailing_padding_size as u8);

    padded_bytes
}

pub fn strip_pkcs_no7_padding(padded_input: &[u8]) -> &[u8] {
    let padded_input_len = padded_input.len();
    let padding_len = padded_input[(padded_input.len() - 1)] as usize;
    let padding_start_ndx = padded_input_len - padding_len;
    &padded_input[..padding_start_ndx]
}
