//! # ConnAck Packet V3
//!
//! This module defines the `ConnAck` packet, which is used in the MQTT protocol to acknowledge
//! a connection request from a client. The `ConnAck` packet contains a `ConnectReturnCode` that
//! indicates the result of the connection attempt.

use crate::codec::util::decode_byte;
use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::v4::ConnectReturnCode;
use crate::protocol::{FixedHeader, PacketType};
use crate::Error;
use bytes::{Buf, BufMut, BytesMut};

/// Represents an MQTT `ConnAck` packet.
///
/// The `ConnAck` packet is sent by the server to the client in response to a `Connect` request.
/// It contains a `ConnectReturnCode` that indicates the result of the connection attempt.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ConnAck(ConnectReturnCode);

impl ConnAck {
    /// Creates a new `ConnAck` packet with the specified return code.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mqute_codec::protocol::v4::ConnectReturnCode;
    /// use mqute_codec::protocol::v3::ConnAck;
    ///
    /// let connack = ConnAck::new(ConnectReturnCode::Success);
    /// ```
    pub fn new(code: ConnectReturnCode) -> Self {
        ConnAck(code)
    }

    /// Returns the `ConnectReturnCode` contained in the `ConnAck` packet.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mqute_codec::protocol::v4::ConnectReturnCode;
    /// use mqute_codec::protocol::v3::ConnAck;
    ///
    /// let connack = ConnAck::new(ConnectReturnCode::Success);
    /// let code = connack.code();
    /// assert_eq!(code, ConnectReturnCode::Success);
    /// ```
    pub fn code(&self) -> ConnectReturnCode {
        self.0
    }
}

impl Decode for ConnAck {
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::ConnAck || !packet.header.flags().is_default()
        {
            return Err(Error::MalformedPacket);
        }

        // Skip the unused byte
        packet.payload.advance(1);

        let ret_code = decode_byte(&mut packet.payload)?;
        let code = ret_code.try_into()?;

        Ok(ConnAck(code))
    }
}

impl Encode for ConnAck {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::ConnAck, self.payload_len());
        header.encode(buf)?;

        // Write a zero byte (reserved byte in ConnAck)
        buf.put_u8(0);

        // Write the connect return code
        buf.put_u8(self.0.into());
        Ok(())
    }

    fn payload_len(&self) -> usize {
        // The payload length for a `ConnAck` packet is always 2 bytes:
        // 1 byte for the reserved byte.
        // 1 byte for the return code.
        2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    #[test]
    fn connack_decode() {
        let mut codec = PacketCodec::new(None, None);

        let data = &[
            (PacketType::ConnAck as u8) << 4, // Packet type
            0x02,                             // Remaining len
            0x00,                             // Connect Acknowledge Flags
            0x00,                             // Connect Return code
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = ConnAck::decode(raw_packet).unwrap();

        assert_eq!(packet, ConnAck::new(ConnectReturnCode::Success));
    }

    #[test]
    fn connack_encode() {
        let packet = ConnAck::new(ConnectReturnCode::Success);

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(
            stream,
            vec![(PacketType::ConnAck as u8) << 4, 0x02, 0x00, 0x00]
        );
    }
}
