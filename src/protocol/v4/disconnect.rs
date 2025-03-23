//! # Disconnect Packet V4
//!
//! This module defines the `Disconnect` packet, which is used in the MQTT protocol to indicate
//! that the client or server is disconnecting from the session. The `Disconnect` packet has no
//! payload and is represented by a simple struct.

use super::util;
use crate::protocol::PacketType;

/// Represents an MQTT `DISCONNECT` packet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Disconnect {}

// Implement the `Decode` trait for `Disconnect`.
util::header_packet_decode_impl!(Disconnect, PacketType::Disconnect);

// Implement the `Encode` trait for `Disconnect`.
util::header_packet_encode_impl!(Disconnect, PacketType::Disconnect);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use crate::codec::{Decode, Encode};
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    #[test]
    fn disconnect_decode() {
        let mut codec = PacketCodec::new(None, None);

        let data = &[
            (PacketType::Disconnect as u8) << 4, // Packet type
            0x00,                                // Remaining len
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = Disconnect::decode(raw_packet).unwrap();

        assert_eq!(packet, Disconnect::default());
    }

    #[test]
    fn disconnect_encode() {
        let packet = Disconnect::default();

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(stream, vec![(PacketType::Disconnect as u8) << 4, 0x00]);
    }
}
