//! # ConnAck Packet V4
//!
//! This module defines the `ConnectReturnCode` enum and the `ConnAck` struct, which are used
//! in the MQTT protocol to represent the result of a connection request and the corresponding
//! acknowledgment packet.

use crate::codec::util::decode_byte;
use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::{FixedHeader, PacketType};
use crate::Error;
use bit_field::BitField;
use bytes::{BufMut, BytesMut};

/// Represents the return codes for a connection attempt in the MQTT protocol.
///
/// The `ConnectReturnCode` enum is used in the `ConnAck` packet to indicate the result
/// of a client's connection request.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectReturnCode {
    /// Connection Accepted
    Success = 0,

    /// The Server does not support the level of the MQTT protocol requested by the Client
    UnacceptableProtocolVersion,

    /// The Client identifier is correct UTF-8 but not allowed by the Server
    IdentifierRejected,

    /// The Network Connection has been made but the MQTT service is unavailable
    ServerUnavailable,

    /// The data in the username or password is malformed
    BadAuthData,

    /// The Client is not authorized to connect
    NotAuthorized,
}

impl TryFrom<u8> for ConnectReturnCode {
    type Error = Error;

    /// Converts a `u8` value into a `ConnectReturnCode`.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let code = match value {
            0 => ConnectReturnCode::Success,
            1 => ConnectReturnCode::UnacceptableProtocolVersion,
            2 => ConnectReturnCode::IdentifierRejected,
            3 => ConnectReturnCode::ServerUnavailable,
            4 => ConnectReturnCode::BadAuthData,
            5 => ConnectReturnCode::NotAuthorized,
            _ => return Err(Error::InvalidConnectReturnCode(value)),
        };

        Ok(code)
    }
}

impl From<ConnectReturnCode> for u8 {
    /// Converts a `ConnectReturnCode` into a `u8` value.
    fn from(value: ConnectReturnCode) -> Self {
        value as u8
    }
}

/// Represents an MQTT `ConnAck` packet.
///
/// # Example
///
/// ```rust
/// use mqute_codec::protocol::v4::{ConnectReturnCode, ConnAck};
///
/// let connack = ConnAck::new(ConnectReturnCode::Success, true);
/// assert_eq!(connack.code(), ConnectReturnCode::Success);
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ConnAck {
    code: ConnectReturnCode,
    session_present: bool,
}

impl ConnAck {
    /// Creates a new `ConnAck` packet with the specified return code and session present flag.
    pub fn new(code: ConnectReturnCode, session_present: bool) -> Self {
        ConnAck {
            code,
            session_present,
        }
    }

    /// Returns the `ConnectReturnCode` contained in the `ConnAck` packet.
    pub fn code(&self) -> ConnectReturnCode {
        self.code
    }

    /// Returns the `session_present` flag from the `ConnAck` packet.
    pub fn session_present(&self) -> bool {
        self.session_present
    }
}

impl Decode for ConnAck {
    /// Decodes a `ConnAck` packet from a raw MQTT packet.
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::ConnAck || !packet.header.flags().is_default()
        {
            return Err(Error::MalformedPacket);
        }

        let conn_ack_flag = decode_byte(&mut packet.payload)?;
        let ret_code = decode_byte(&mut packet.payload)?;
        let code = ret_code.try_into()?;
        let session_present = conn_ack_flag.get_bit(0);

        Ok(ConnAck {
            code,
            session_present,
        })
    }
}

impl Encode for ConnAck {
    /// Encodes the `ConnAck` packet into a byte buffer.
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::ConnAck, self.payload_len());
        header.encode(buf)?;

        let mut flags = 0u8;
        flags.set_bit(0, self.session_present);

        // Write the session present flag
        buf.put_u8(flags);

        // Write the connect return code
        buf.put_u8(self.code.into());
        Ok(())
    }

    /// Returns the length of the `ConnAck` packet payload.
    fn payload_len(&self) -> usize {
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
            0x01,                             // Connect Acknowledge Flags
            0x00,                             // Connect Return code
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = ConnAck::decode(raw_packet).unwrap();

        assert_eq!(packet, ConnAck::new(ConnectReturnCode::Success, true));
    }

    #[test]
    fn connack_encode() {
        let packet = ConnAck::new(ConnectReturnCode::Success, true);

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(
            stream,
            vec![(PacketType::ConnAck as u8) << 4, 0x02, 0x01, 0x00]
        );
    }
}
