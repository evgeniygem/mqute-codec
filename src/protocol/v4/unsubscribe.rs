//! # Unsubscribe Packet V4
//!
//! This module defines the `Unsubscribe` packet, which is used in the MQTT protocol to request
//! the removal of one or more topic filters from a subscription. The `Unsubscribe` packet
//! includes a packet ID and a list of topic filters.

use crate::codec::util::decode_word;
use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::{FixedHeader, Flags, PacketType, QoS, TopicFilters};
use crate::Error;
use bytes::{BufMut, BytesMut};

/// Represents an MQTT `Unsubscribe` packet.
///
/// # Example
///
/// ```rust
/// use mqute_codec::protocol::TopicFilters;
/// use mqute_codec::protocol::v4::Unsubscribe;
///
/// let unsubscribe = Unsubscribe::new(1234, vec!["topic1", "topic2"]);
///
/// let filters = TopicFilters::new(vec!["topic1", "topic2"]);
///
/// assert_eq!(unsubscribe.packet_id(), 1234u16);
/// assert_eq!(unsubscribe.filters(), filters);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsubscribe {
    /// The packet ID for the `Unsubscribe` packet.
    packet_id: u16,

    /// The list of topic filters to unsubscribe from.
    filters: TopicFilters,
}

impl Unsubscribe {
    /// Creates a new `Unsubscribe` packet.
    ///
    /// # Panics
    ///
    /// Panics if `packet_id` is zero.
    pub fn new<T: IntoIterator<Item: Into<String>>>(packet_id: u16, filters: T) -> Self {
        if packet_id == 0 {
            panic!("Packet id is zero");
        }

        Unsubscribe {
            packet_id,
            filters: TopicFilters::new(filters),
        }
    }

    /// Returns the packet ID of the `Unsubscribe` packet.
    pub fn packet_id(&self) -> u16 {
        self.packet_id
    }

    /// Returns the list of topic filters to unsubscribe from.
    pub fn filters(&self) -> TopicFilters {
        self.filters.clone()
    }
}

impl Decode for Unsubscribe {
    /// Decodes an `Unsubscribe` packet from a raw MQTT packet.
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::Unsubscribe
            || packet.header.flags() != Flags::new(QoS::AtLeastOnce)
        {
            return Err(Error::MalformedPacket);
        }

        let packet_id = decode_word(&mut packet.payload)?;
        let filters = TopicFilters::decode(&mut packet.payload)?;

        Ok(Unsubscribe::new(packet_id, filters))
    }
}

impl Encode for Unsubscribe {
    /// Encodes the `Unsubscribe` packet into a byte buffer.
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::with_flags(
            PacketType::Unsubscribe,
            Flags::new(QoS::AtLeastOnce),
            self.payload_len(),
        );
        header.encode(buf)?;

        // Encode the packet id
        buf.put_u16(self.packet_id);
        self.filters.encode(buf);
        Ok(())
    }

    fn payload_len(&self) -> usize {
        2 + self.filters.encoded_len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    fn packet_data() -> &'static [u8] {
        &[
            (PacketType::Unsubscribe as u8) << 4 | 0b0010, // Packet type
            0x16,                                          // Remaining len
            0x12,                                          // Packet ID
            0x34,                                          //
            0x00,                                          // Topic #1 len
            0x0c,                                          //
            b'h',                                          // Topic message
            b'e',
            b'l',
            b'l',
            b'o',
            b' ',
            b'w',
            b'o',
            b'r',
            b'l',
            b'd',
            b'!',
            0x00, // Topic #2 len
            0x04,
            b't', // Topic message
            b'e',
            b's',
            b't',
        ]
    }

    #[test]
    fn unsubscribe_decode() {
        let mut codec = PacketCodec::new(None, None);

        let mut stream = BytesMut::new();

        stream.extend_from_slice(packet_data());

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = Unsubscribe::decode(raw_packet).unwrap();

        assert_eq!(
            packet,
            Unsubscribe::new(0x1234, vec!["hello world!", "test"])
        );
    }

    #[test]
    fn unsubscribe_encode() {
        let packet = Unsubscribe::new(0x1234, vec!["hello world!", "test"]);

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(stream, Vec::from(packet_data()));
    }

    #[test]
    #[should_panic]
    fn unsubscribe_construct() {
        Unsubscribe::new(0, Vec::<String>::new());
    }
}
