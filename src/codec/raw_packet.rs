use crate::header::FixedHeader;
use bytes::Bytes;

pub struct RawPacket {
    // Fixed header
    pub header: FixedHeader,

    // Variable header and payload
    pub payload: Bytes,
}

impl RawPacket {
    pub fn new(header: FixedHeader, payload: Bytes) -> Self {
        if header.remaining_len() != payload.len() {
            panic!("Header and payload mismatch");
        }
        RawPacket { header, payload }
    }
}
