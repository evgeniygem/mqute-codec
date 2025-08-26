//! # SubAck Packet V3
//!
//! This module initializes the `SubAck` packet for MQTT protocol.
//! It uses the `suback!` macro to define the `SubAck` packet structure with support
//! for Quality of Service (QoS) levels.

use crate::Error;
use crate::protocol::common::suback;
use crate::protocol::{QoS, traits};

/// Represents the return codes for a `SubAck` packet.
///
/// # Example
///
/// ```rust
/// use mqute_codec::protocol::QoS;
/// use crate::mqute_codec::protocol::v3::ReturnCode;
///
/// let retcode = ReturnCode::new(QoS::AtMostOnce);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReturnCode(QoS);

impl ReturnCode {
    pub fn new(qos: QoS) -> Self {
        ReturnCode { 0: qos }
    }
}

impl TryFrom<u8> for ReturnCode {
    type Error = Error;

    /// Converts a `u8` value into a `ReturnCode`.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let code = match value {
            0x0 => ReturnCode(QoS::AtMostOnce),
            0x1 => ReturnCode(QoS::AtLeastOnce),
            0x2 => ReturnCode(QoS::ExactlyOnce),
            _ => return Err(Error::InvalidReasonCode(value)),
        };

        Ok(code)
    }
}

impl From<ReturnCode> for u8 {
    /// Converts a `ReturnCode` into a `u8` value.
    fn from(value: ReturnCode) -> Self {
        value.0 as Self
    }
}

suback!(ReturnCode);

impl traits::SubAck for SubAck {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Decode, Encode, PacketCodec};
    use crate::protocol::PacketType;
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    #[test]
    fn suback_decode() {
        let mut codec = PacketCodec::new(None, None);

        let data = &[
            (PacketType::SubAck as u8) << 4, // Packet type
            0x05,                            // Remaining len
            0x12,                            // Packet ID
            0x34,
            0x00, // QoS 0
            0x01, // QoS 1
            0x02, // QoS 2
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = SubAck::decode(raw_packet).unwrap();

        assert_eq!(
            packet,
            SubAck::new(
                0x1234,
                vec![
                    ReturnCode(QoS::AtMostOnce),
                    ReturnCode(QoS::AtLeastOnce),
                    ReturnCode(QoS::ExactlyOnce)
                ]
            )
        );
    }

    #[test]
    fn suback_encode() {
        let packet = SubAck::new(
            0x1234,
            vec![
                ReturnCode(QoS::AtMostOnce),
                ReturnCode(QoS::AtLeastOnce),
                ReturnCode(QoS::ExactlyOnce),
            ],
        );

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(
            stream,
            vec![
                (PacketType::SubAck as u8) << 4,
                0x05,
                0x12,
                0x34,
                0x00, // QoS 0
                0x01, // QoS 1
                0x02, // QoS 2
            ]
        );
    }
}
