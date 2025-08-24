//! # Publish Packet V4
//!
//! This module defines the `Publish` packet, which is used in the MQTT protocol to send
//! messages from a client to a server or from a server to a client. The `Publish` packet
//! includes a topic, payload, and flags for QoS, retain, and duplicate delivery.

use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::common::PublishHeader;
use crate::protocol::{FixedHeader, Flags, PacketType, QoS};
use crate::Error;
use bytes::{Bytes, BytesMut};

/// Represents an MQTT `Publish` packet.
///
/// # Example
///
/// ```rust
/// use mqute_codec::protocol::v4::Publish;
/// use mqute_codec::protocol::{QoS, Flags};
/// use bytes::Bytes;
///
/// let flags = Flags::new(QoS::AtLeastOnce);
/// let publish = Publish::new("topic", 1234, Bytes::from("message"), flags);
///
/// assert_eq!(publish.flags(), flags);
/// assert_eq!(publish.topic(), "topic");
/// assert_eq!(publish.packet_id(), Some(1234));
/// assert_eq!(publish.payload(), Bytes::from("message"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    /// The header of the `Publish` packet, containing the topic and packet ID (for QoS > 0).
    header: PublishHeader,

    /// The payload of the `Publish` packet, containing the message data.
    payload: Bytes,

    /// The flags for the `Publish` packet, including QoS, retain, and duplicate delivery.
    flags: Flags,
}

impl Publish {
    /// Creates a new `Publish` packet.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `packet_id` is zero for QoS > 0.
    /// - The topic name is invalid according to MQTT topic naming rules.
    pub fn new<T: Into<String>>(topic: T, packet_id: u16, payload: Bytes, flags: Flags) -> Self {
        if flags.qos != QoS::AtMostOnce && packet_id == 0 {
            panic!("Control packets must contain a non-zero packet identifier at QoS > 0");
        }

        Publish {
            header: PublishHeader::new(topic, packet_id),
            payload,
            flags,
        }
    }

    /// Returns the flags for the `Publish` packet.
    ///
    /// The flags include QoS, retain, and duplicate delivery settings.
    pub fn flags(&self) -> Flags {
        self.flags
    }

    /// Returns the topic of the `Publish` packet.
    pub fn topic(&self) -> String {
        self.header.topic.clone()
    }

    /// Returns the packet ID of the `Publish` packet.
    ///
    /// For QoS 0, this method returns `None` because no packet ID is used.
    /// For QoS 1 and 2, it returns the packet ID as `Some(u16)`.
    pub fn packet_id(&self) -> Option<u16> {
        if self.flags.qos != QoS::AtMostOnce {
            Some(self.header.packet_id)
        } else {
            None
        }
    }

    /// Returns the payload of the `Publish` packet.
    pub fn payload(&self) -> Bytes {
        self.payload.clone()
    }
}

impl Decode for Publish {
    /// Decodes a `Publish` packet from a raw MQTT packet.
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::Publish {
            return Err(Error::MalformedPacket);
        }

        let flags = packet.header.flags();

        let publish_header = PublishHeader::decode(&mut packet.payload, flags.qos)?;

        let packet = Publish {
            header: publish_header,
            payload: packet.payload,
            flags,
        };
        Ok(packet)
    }
}

impl Encode for Publish {
    /// Encodes the `Publish` packet into a byte buffer.
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::with_flags(PacketType::Publish, self.flags, self.payload_len());
        header.encode(buf)?;
        self.header.encode(buf, self.flags.qos);

        // Append message
        buf.extend_from_slice(&self.payload);
        Ok(())
    }

    /// Returns the length of the `Publish` packet payload.
    ///
    /// The payload length includes the length of the Publish header and the message payload.
    fn payload_len(&self) -> usize {
        self.header.encoded_len(self.flags.qos) + self.payload.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use crate::protocol::QoS;
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    #[test]
    fn publish_decode() {
        let mut codec = PacketCodec::new(None, None);

        let payload: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        let data = &[
            (PacketType::Publish as u8) << 4 | 0b0000_0100, // Packet type
            0x0d,                                           // Remaining len
            0x00,
            0x05,
            b'/',
            b't',
            b'e',
            b's',
            b't',
            0x12,
            0x34,
            0xde,
            0xad,
            0xbe,
            0xef,
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = Publish::decode(raw_packet).unwrap();

        assert_eq!(
            packet,
            Publish::new(
                "/test",
                0x1234,
                Bytes::copy_from_slice(&payload),
                Flags::new(QoS::ExactlyOnce)
            )
        );
    }

    #[test]
    fn publish_encode() {
        let payload: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        let packet = Publish::new(
            "/test",
            0x1234,
            Bytes::copy_from_slice(&payload),
            Flags::new(QoS::ExactlyOnce),
        );

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(
            stream,
            vec![
                (PacketType::Publish as u8) << 4 | 0b0000_0100, // Packet type
                0x0d,                                           // Remaining len
                0x00,
                0x05,
                b'/',
                b't',
                b'e',
                b's',
                b't',
                0x12,
                0x34,
                0xde,
                0xad,
                0xbe,
                0xef,
            ]
        );
    }
}
