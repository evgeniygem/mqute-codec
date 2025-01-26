#[inline]
pub(crate) fn remaining_len_bytes(len: usize) -> usize {
    if len < 128 {
        1
    } else if len < 16_384 {
        2
    } else if len < 2_097_152 {
        3
    } else if len < 268_435_456 {
        4
    } else {
        panic!("Length of remaining bytes must be less than 28 bits")
    }
}
