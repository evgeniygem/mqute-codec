//! # Subscribe Packet V4
//!
//! This module defines the `Subscribe` packet and related structures (`TopicQosFilter` and
//! `TopicQosFilters`) used in the MQTT protocol to handle subscription requests. The `Subscribe`
//! packet contains a list of topic filters and their requested QoS levels.

use crate::Error;
use crate::codec::util::{decode_byte, decode_string, decode_word, encode_string};
use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::{FixedHeader, Flags, PacketType, QoS, util};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::borrow::Borrow;

/// Represents a single topic filter and its requested QoS level.
///
/// # Example
///
/// ```rust
/// use mqute_codec::protocol::v4::TopicQosFilter;
/// use mqute_codec::protocol::QoS;
///
/// let filter = TopicQosFilter::new("topic1", QoS::AtLeastOnce);
/// assert_eq!(filter.topic, "topic1");
/// assert_eq!(filter.qos, QoS::AtLeastOnce);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicQosFilter {
    /// The topic filter for the subscription.
    pub topic: String,

    /// The requested QoS level for the subscription.
    pub qos: QoS,
}

impl TopicQosFilter {
    /// Creates a new `TopicQosFilter` instance with the specified topic and QoS level.
    ///
    /// # Panics
    ///
    /// Panics if the topic filter is invalid according to MQTT specification rules.
    pub fn new<T: Into<String>>(topic: T, qos: QoS) -> Self {
        let topic = topic.into();

        if !util::is_valid_topic_filter(&topic) {
            panic!("Invalid topic filter: '{}'", topic);
        }

        Self { topic, qos }
    }
}

/// Represents a collection of `TopicQosFilter` instances.
///
/// # Example
///
/// ```rust
/// use mqute_codec::protocol::v4::{Subscribe, TopicQosFilters, TopicQosFilter};
/// use mqute_codec::protocol::QoS;
///
/// let topic_filters = TopicQosFilters::new(vec![
///         TopicQosFilter::new("topic1", QoS::AtLeastOnce),
///         TopicQosFilter::new("topic2", QoS::ExactlyOnce),
///     ]);
///
/// assert_eq!(topic_filters.len(), 2);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicQosFilters(Vec<TopicQosFilter>);

#[allow(clippy::len_without_is_empty)]
impl TopicQosFilters {
    /// Creates a new `TopicQosFilters` instance from an iterator of `TopicQosFilter`.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - The iterator is empty, as at least one topic filter is required.
    /// - The topic filters are invalid according to MQTT topic naming rules.
    pub fn new<T: IntoIterator<Item = TopicQosFilter>>(filters: T) -> Self {
        let values: Vec<TopicQosFilter> = filters.into_iter().collect();

        if values.is_empty() {
            panic!("At least one topic filter is required");
        }

        TopicQosFilters(values)
    }

    /// Returns the number of topic filters in the collection.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn decode(payload: &mut Bytes) -> Result<Self, Error> {
        let mut filters = Vec::with_capacity(1);

        while payload.has_remaining() {
            let filter = decode_string(payload)?;

            if !util::is_valid_topic_filter(&filter) {
                return Err(Error::InvalidTopicFilter(filter));
            }

            let flags = decode_byte(payload)?;

            // The upper 6 bits of the Requested QoS byte must be zero
            if flags & 0b1111_1100 > 0 {
                return Err(Error::MalformedPacket);
            }

            filters.push(TopicQosFilter::new(filter, flags.try_into()?));
        }

        if filters.is_empty() {
            return Err(Error::NoTopic);
        }

        Ok(TopicQosFilters(filters))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        self.0.iter().for_each(|f| {
            encode_string(buf, &f.topic);
            buf.put_u8(f.qos.into());
        });
    }

    pub(crate) fn encoded_len(&self) -> usize {
        self.0.iter().fold(0, |acc, f| acc + 2 + f.topic.len() + 1)
    }
}

impl AsRef<Vec<TopicQosFilter>> for TopicQosFilters {
    #[inline]
    fn as_ref(&self) -> &Vec<TopicQosFilter> {
        self.0.as_ref()
    }
}

impl Borrow<Vec<TopicQosFilter>> for TopicQosFilters {
    fn borrow(&self) -> &Vec<TopicQosFilter> {
        self.0.as_ref()
    }
}

impl IntoIterator for TopicQosFilters {
    type Item = TopicQosFilter;
    type IntoIter = std::vec::IntoIter<TopicQosFilter>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl FromIterator<TopicQosFilter> for TopicQosFilters {
    fn from_iter<T: IntoIterator<Item = TopicQosFilter>>(iter: T) -> Self {
        TopicQosFilters(Vec::from_iter(iter))
    }
}

impl From<TopicQosFilters> for Vec<TopicQosFilter> {
    #[inline]
    fn from(value: TopicQosFilters) -> Self {
        value.0
    }
}

impl From<Vec<TopicQosFilter>> for TopicQosFilters {
    #[inline]
    fn from(value: Vec<TopicQosFilter>) -> Self {
        TopicQosFilters(value)
    }
}

/// Represents an MQTT `Subscribe` packet.
///
/// # Example
///
/// ```rust
/// use mqute_codec::protocol::v4::{Subscribe, TopicQosFilter};
/// use mqute_codec::protocol::QoS;
///
/// let filters = vec![
///     TopicQosFilter::new("topic1", QoS::AtLeastOnce),
///     TopicQosFilter::new("topic2", QoS::ExactlyOnce),
/// ];
/// let subscribe = Subscribe::new(123, filters);
/// assert_eq!(subscribe.packet_id(), 123);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscribe {
    /// The packet ID for the `Subscribe` packet.
    packet_id: u16,

    /// The list of topic filters and their requested QoS levels.
    filters: TopicQosFilters,
}

impl Subscribe {
    /// Creates a new `Subscribe` packet.
    ///
    /// # Panics
    ///
    /// Panics if `packet_id` is zero.
    pub fn new<T: IntoIterator<Item = TopicQosFilter>>(packet_id: u16, filters: T) -> Self {
        if packet_id == 0 {
            panic!("Packet id is zero");
        }

        let filters = filters.into_iter().collect();
        Subscribe { packet_id, filters }
    }

    /// Returns the packet ID of the `Subscribe` packet.
    pub fn packet_id(&self) -> u16 {
        self.packet_id
    }

    /// Returns the list of topic filters and their requested QoS levels.
    pub fn filters(&self) -> TopicQosFilters {
        self.filters.clone()
    }
}

impl Decode for Subscribe {
    /// Decodes a `Subscribe` packet from a raw MQTT packet.
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        // Validate header flags
        if packet.header.packet_type() != PacketType::Subscribe
            || packet.header.flags() != Flags::new(QoS::AtLeastOnce)
        {
            return Err(Error::MalformedPacket);
        }

        let packet_id = decode_word(&mut packet.payload)?;
        let filters = TopicQosFilters::decode(&mut packet.payload)?;

        Ok(Subscribe::new(packet_id, filters))
    }
}

impl Encode for Subscribe {
    /// Encodes the `Subscribe` packet into a byte buffer.
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::with_flags(
            PacketType::Subscribe,
            Flags::new(QoS::AtLeastOnce),
            self.payload_len(),
        );
        header.encode(buf)?;
        buf.put_u16(self.packet_id);
        self.filters.encode(buf);

        Ok(())
    }

    /// Returns the length of the `Subscribe` packet payload.
    fn payload_len(&self) -> usize {
        // Packet ID and filter list
        2 + self.filters.encoded_len()
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
    fn subscribe_decode() {
        let mut codec = PacketCodec::new(None, None);

        let data = &[
            (PacketType::Subscribe as u8) << 4 | 0b0010, // Packet type
            0x0c,                                        // Remaining len
            0x12,
            0x34,
            0x00,
            0x02,
            b'/',
            b'a',
            0x00,
            0x00,
            0x02,
            b'/',
            b'b',
            0x02,
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = Subscribe::decode(raw_packet).unwrap();

        assert_eq!(
            packet,
            Subscribe::new(
                0x1234,
                vec![
                    TopicQosFilter::new("/a", QoS::AtMostOnce),
                    TopicQosFilter::new("/b", QoS::ExactlyOnce)
                ]
            )
        );
    }

    #[test]
    fn subscribe_encode() {
        let packet = Subscribe::new(
            0x1234,
            vec![
                TopicQosFilter::new("/a", QoS::AtMostOnce),
                TopicQosFilter::new("/b", QoS::ExactlyOnce),
            ],
        );

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(
            stream,
            vec![
                (PacketType::Subscribe as u8) << 4 | 0b0010, // Packet type
                0x0c,                                        // Remaining len
                0x12,
                0x34,
                0x00,
                0x02,
                b'/',
                b'a',
                0x00,
                0x00,
                0x02,
                b'/',
                b'b',
                0x02,
            ]
        );
    }
}
