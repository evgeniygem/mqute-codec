use crate::packet::PacketType;
use bit_field::BitField;

#[inline]
pub(crate) fn fetch_packet_type(control_byte: u8) -> u8 {
    control_byte >> 4
}

#[inline]
pub(crate) fn fetch_flags(control_byte: u8) -> u8 {
    control_byte & 0x0F
}

#[inline]
pub(crate) fn build_control_byte(packet_type: PacketType, flags: u8) -> u8 {
    let mut byte = (packet_type as u8) << 4;

    // Panics if the flag is greater than 4 bits
    byte.set_bits(0..4, flags);
    byte
}

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
