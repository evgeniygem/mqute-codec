//! # PubAck Packet V4
//!
//! This module defines the `PubAck` packet, which is used in the MQTT protocol to acknowledge
//! the receipt of a `Publish` packet with QoS level 1. The `PubAck` packet contains a packet ID
//! to match it with the corresponding `Publish` packet.

use super::util;
use crate::protocol::{PacketType, traits};

// Defines the `PubAck` packet for MQTT V4
util::id_packet!(PubAck);

// Implement the `Decode` trait for `PubAck`.
util::id_packet_decode_impl!(PubAck, PacketType::PubAck);

// Implement the `Encode` trait for `PubAck`.
util::id_packet_encode_impl!(PubAck, PacketType::PubAck);

impl traits::PubAck for PubAck {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use crate::codec::{Decode, Encode};
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    #[test]
    fn puback_decode() {
        let mut codec = PacketCodec::new(None, None);

        let data = &[
            (PacketType::PubAck as u8) << 4, // Packet type
            0x02,                            // Remaining len
            0x12,                            // Packet ID
            0x34,
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = PubAck::decode(raw_packet).unwrap();

        assert_eq!(packet, PubAck::new(0x1234));
    }

    #[test]
    fn puback_encode() {
        let packet = PubAck::new(0x1234);

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(
            stream,
            vec![(PacketType::PubAck as u8) << 4, 0x02, 0x12, 0x34]
        );
    }
}
