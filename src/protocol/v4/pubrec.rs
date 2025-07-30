//! # PubRec Packet V4
//!
//! This module defines the `PubRec` packet, which is used in the MQTT protocol to acknowledge
//! the receipt of a `Publish` packet with QoS level 2. The `PubRec` packet contains a packet ID
//! to match it with the corresponding `Publish` packet.

use super::util;
use crate::protocol::PacketType;

// Defines the `PubRec` packet for MQTT V4
util::id_packet!(PubRec);

// Implement the `Decode` trait for `PubRec`.
util::id_packet_decode_impl!(PubRec, PacketType::PubRec);

// Implement the `Encode` trait for `PubRec`.
util::id_packet_encode_impl!(PubRec, PacketType::PubRec);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use crate::codec::{Decode, Encode};
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    #[test]
    fn pubrec_decode() {
        let mut codec = PacketCodec::new(None, None);

        let data = &[
            (PacketType::PubRec as u8) << 4, // Packet type
            0x02,                            // Remaining len
            0x12,                            // Packet ID
            0x34,
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = PubRec::decode(raw_packet).unwrap();

        assert_eq!(packet, PubRec::new(0x1234));
    }

    #[test]
    fn pubrec_encode() {
        let packet = PubRec::new(0x1234);

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(
            stream,
            vec![(PacketType::PubRec as u8) << 4, 0x02, 0x12, 0x34]
        );
    }
}
