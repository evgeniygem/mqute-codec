//! # Ping Request and Response Packets V5
//!
//! This module implements the MQTT PingReq (Ping Request) and PingResp (Ping Response) packets.
//! These packets are used to maintain the connection between client and server when no other
//! packets are being sent, and to verify that the connection is still active.
//!
//! The PingReq packet is sent by a client to the server to:
//! 1. Indicate that the client is alive when no other packets are being sent
//! 2. Verify that the server is available and responding
//!
//! The PingResp packet is sent by the server in response to a PingReq to:
//! 1. Acknowledge the ping request
//! 2. Confirm that the server is still alive and responsive
//!
//! The PingReq and PingResp packet have no payload or variable header - they consist only of a
//! fixed header.

use super::util;
use crate::protocol::{PacketType, traits};

/// Represents an MQTT PingReq (Ping Request) packet.
///
/// # Example
///
/// ```rust
/// use mqute_codec::protocol::v5::PingReq;
///
/// let packet = PingReq { };
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PingReq {}

// Implements encoding/decoding using ping packet macros
util::ping_packet_decode_impl!(PingReq, PacketType::PingReq);
util::ping_packet_encode_impl!(PingReq, PacketType::PingReq);

impl traits::PingReq for PingReq {}

/// Represents an MQTT PingResp (Ping Response) packet.
///
/// # Example
///
/// ```rust
/// use mqute_codec::protocol::v5::PingResp;
///
/// let packet = PingResp { };
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PingResp {}

// Implements encoding/decoding using ping packet macros
util::ping_packet_decode_impl!(PingResp, PacketType::PingResp);
util::ping_packet_encode_impl!(PingResp, PacketType::PingResp);

impl traits::PingResp for PingResp {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use crate::codec::{Decode, Encode};
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    #[test]
    fn pingreq_decode() {
        let mut codec = PacketCodec::new(None, None);

        let data = &[
            (PacketType::PingReq as u8) << 4, // Packet type
            0x00,                             // Remaining len
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = PingReq::decode(raw_packet).unwrap();

        assert_eq!(packet, PingReq::default());
    }

    #[test]
    fn pingreq_encode() {
        let packet = PingReq::default();

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(stream, vec![(PacketType::PingReq as u8) << 4, 0x00]);
    }

    #[test]
    fn pingresp_decode() {
        let mut codec = PacketCodec::new(None, None);

        let data = &[
            (PacketType::PingResp as u8) << 4, // Packet type
            0x00,                              // Remaining len
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = PingResp::decode(raw_packet).unwrap();

        assert_eq!(packet, PingResp::default());
    }

    #[test]
    fn pingresp_encode() {
        let packet = PingResp::default();

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(stream, vec![(PacketType::PingResp as u8) << 4, 0x00]);
    }
}
