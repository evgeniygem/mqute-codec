//! # Unsubscribe Packet - MQTT v5
//!
//! This module implements the MQTT v5 `Unsubscribe` packet, which is sent by clients to
//! request unsubscription from one or more topics. The packet includes the list of
//! topic filters to unsubscribe from and optional properties.

use crate::codec::util::decode_byte;
use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::v5::property::{
    property_decode, property_encode, property_len, Property, PropertyFrame,
};
use crate::protocol::v5::util::id_header;
use crate::protocol::{FixedHeader, Flags, PacketType, QoS, TopicFilters};
use crate::Error;
use bytes::{Buf, Bytes, BytesMut};

/// Properties specific to `Unsubscribe` packets
///
/// In MQTT v5, `Unsubscribe` packets can include:
/// - User Properties (key-value pairs for extended metadata)
///
/// # Example
/// ```rust
/// use mqute_codec::protocol::v5::UnsubscribeProperties;
///
/// let properties = UnsubscribeProperties {
///     user_properties: vec![("client".into(), "rust".into())],
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsubscribeProperties {
    /// User-defined key-value properties
    pub user_properties: Vec<(String, String)>,
}

impl PropertyFrame for UnsubscribeProperties {
    /// Calculates the encoded length of the properties
    fn encoded_len(&self) -> usize {
        let mut len = 0usize;
        len += property_len!(&self.user_properties);
        len
    }

    /// Encodes the properties into a byte buffer
    fn encode(&self, buf: &mut BytesMut) {
        property_encode!(&self.user_properties, Property::UserProp, buf);
    }

    /// Decodes properties from a byte buffer
    fn decode(buf: &mut Bytes) -> Result<Option<Self>, Error>
    where
        Self: Sized,
    {
        if buf.is_empty() {
            return Ok(None);
        }

        let mut user_properties: Vec<(String, String)> = Vec::new();

        while buf.has_remaining() {
            let property: Property = decode_byte(buf)?.try_into()?;
            match property {
                Property::UserProp => {
                    property_decode!(&mut user_properties, buf);
                }
                _ => return Err(Error::PropertyMismatch),
            }
        }

        Ok(Some(UnsubscribeProperties { user_properties }))
    }
}

// Internal header structure for `Unsubscribe` packets
id_header!(UnsubscribeHeader, UnsubscribeProperties);

/// Represents an MQTT v5 `Unsubscribe` packet
///
/// The `Unsubscribe` packet is sent by clients to request removal of existing
/// subscriptions. It contains:
/// - Packet Identifier (for QoS 1 acknowledgment)
/// - List of topic filters to unsubscribe from
/// - Optional properties (v5 only)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsubscribe {
    header: UnsubscribeHeader,
    filters: TopicFilters,
}

impl Unsubscribe {
    /// Creates a new `Unsubscribe` packet
    ///
    /// # Example
    ///
    /// ```rust
    /// use mqute_codec::protocol::v5::{Unsubscribe, UnsubscribeProperties};
    ///
    /// // Simple unsubscribe with no properties
    /// let unsubscribe = Unsubscribe::new(
    ///     1234,
    ///     None,
    ///     vec!["sensors/temperature", "control/#"]
    /// );
    ///
    /// // Unsubscribe with properties
    /// let properties = UnsubscribeProperties {
    ///     user_properties: vec![("reason".into(), "client_shutdown".into())],
    /// };
    /// let unsubscribe = Unsubscribe::new(
    ///     5678,
    ///     Some(properties),
    ///     vec!["debug/logs"]
    /// );
    /// ```
    pub fn new<T: IntoIterator<Item: Into<String>>>(
        packet_id: u16,
        properties: Option<UnsubscribeProperties>,
        filters: T,
    ) -> Self {
        let filters: Vec<String> = filters.into_iter().map(|x| x.into()).collect();

        Unsubscribe {
            header: UnsubscribeHeader::new(packet_id, properties),
            filters: filters.into(),
        }
    }

    /// Returns the packet identifier
    ///
    /// # Example
    ///
    /// ```rust
    /// use mqute_codec::protocol::v5::{Unsubscribe, UnsubscribeProperties};
    ///
    /// // Simple unsubscribe with no properties
    /// let unsubscribe = Unsubscribe::new(
    ///     1234,
    ///     None,
    ///     vec!["sensors/temperature", "control/#"]
    /// );
    /// assert_eq!(unsubscribe.packet_id(), 1234u16);
    /// ```
    pub fn packet_id(&self) -> u16 {
        self.header.packet_id
    }

    /// Returns the unsubscribe properties
    ///
    /// # Example
    ///
    /// ```rust
    /// use mqute_codec::protocol::v5::{Unsubscribe, UnsubscribeProperties};
    ///
    /// // Unsubscribe with properties
    /// let properties = UnsubscribeProperties {
    ///     user_properties: vec![("reason".into(), "client_shutdown".into())],
    /// };
    /// let unsubscribe = Unsubscribe::new(
    ///     5678,
    ///     Some(properties.clone()),
    ///     vec!["debug/logs"]
    /// );
    ///
    /// assert_eq!(unsubscribe.properties(), Some(properties));
    /// ```
    pub fn properties(&self) -> Option<UnsubscribeProperties> {
        self.header.properties.clone()
    }

    /// Returns the topic filters to unsubscribe from
    ///
    /// # Example
    ///
    /// ```rust
    /// use mqute_codec::protocol::TopicFilters;
    /// use mqute_codec::protocol::v5::{Unsubscribe, UnsubscribeProperties};
    ///
    /// let unsubscribe = Unsubscribe::new(
    ///     5678,
    ///     None,
    ///     vec!["debug/logs"]
    /// );
    ///
    /// assert_eq!(unsubscribe.filters(), TopicFilters::new(vec!["topic1", "topic2"]));
    /// ```
    pub fn filters(&self) -> TopicFilters {
        self.filters.clone()
    }
}

impl Encode for Unsubscribe {
    /// Encodes the `Unsubscribe` packet into a byte buffer
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::with_flags(
            PacketType::Unsubscribe,
            Flags::new(QoS::AtLeastOnce),
            self.payload_len(),
        );
        header.encode(buf)?;

        self.header.encode(buf)?;
        self.filters.encode(buf);
        Ok(())
    }

    /// Calculates the total packet length
    fn payload_len(&self) -> usize {
        self.header.encoded_len() + self.filters.encoded_len()
    }
}

impl Decode for Unsubscribe {
    /// Decodes an `Unsubscribe` packet from raw bytes
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        // Validate header flags
        if packet.header.packet_type() != PacketType::Unsubscribe
            || packet.header.flags() != Flags::new(QoS::AtLeastOnce)
        {
            return Err(Error::MalformedPacket);
        }

        let header = UnsubscribeHeader::decode(&mut packet.payload)?;
        let filters = TopicFilters::decode(&mut packet.payload)?;

        Ok(Unsubscribe::new(
            header.packet_id,
            header.properties,
            filters,
        ))
    }
}
