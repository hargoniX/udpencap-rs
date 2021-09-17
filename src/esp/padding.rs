/// Applies the 1,2,3... ESP padding to buf
///
/// inside of `buf`. It will pad `buf` so it aligns with `block_size`,
/// given that `payload_len` bytes are inside of buf. and assuming the
/// pad length and next_header fields will be added later on)
///
/// It returns the length it padded.
///
/// Note that the function assumes buf has enough space to fit the padding
/// and is going to panic otherwise.
pub fn pad(buf: &mut [u8], payload_len: usize, block_size: usize) -> u8 {
    let pad_len = pad_len(payload_len, block_size);
    for pad in 0..pad_len {
        // 8 + since SPI + sequence number are in the beginning of the packet
        buf[pad as usize + payload_len] = pad + 1;
    }
    pad_len
}

pub const fn pad_len(payload_len: usize, block_size: usize) -> u8 {
    // + 2 since pad length + next_header field are still missing and
    // will be added later on.
    (block_size - ((payload_len + 2) % block_size)) as u8
}
