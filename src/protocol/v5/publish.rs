//! # Publish Packet - MQTT v5
//!
//! This module implements the MQTT v5 `Publish` packet, which is used to transport
//! application messages between clients and servers. The packet supports all three
//! QoS levels and includes extensive message properties for enhanced functionality.

use super::property::{Property, PropertyFrame, property_decode, property_encode, property_len};
use crate::Error;
use crate::codec::util::{decode_byte, decode_variable_integer, encode_variable_integer};
use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::util::len_bytes;
use crate::protocol::{FixedHeader, Flags, PacketType, QoS, common};
use bytes::{Buf, Bytes, BytesMut};
use std::time::Duration;

/// Represents properties of a `Publish` packet in MQTT v5
///
/// These properties provide extended message metadata including:
/// - Message formatting hints
/// - Expiration timing
/// - Topic aliasing
/// - Response routing
/// - Correlation data
/// - Subscription identifiers
/// - Content type information
///
/// # Example
///
/// ```rust
/// use bytes::Bytes;
/// use std::time::Duration;
/// use mqute_codec::protocol::v5::PublishProperties;
///
/// let properties = PublishProperties {
///     payload_format_indicator: Some(1), // UTF-8 payload
///     message_expiry_interval: Some(Duration::from_secs(3600)), // Expires in 1 hour
///     topic_alias: Some(5), // Use topic alias ID 5
///     response_topic: Some("response/topic".into()),
///     correlation_data: Some(Bytes::from("correlation-id")),
///     user_properties: vec![("priority".into(), "high".into())],
///     subscription_id: vec![42], // Subscription ID
///     content_type: Some("application/json".into()),
/// };
/// ```
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PublishProperties {
    /// Indicates payload format (0=bytes, 1=UTF-8)
    pub payload_format_indicator: Option<u8>,
    /// Message lifetime in seconds
    pub message_expiry_interval: Option<Duration>,
    /// Topic alias for message routing
    pub topic_alias: Option<u16>,
    /// Topic for response messages
    pub response_topic: Option<String>,
    /// Correlation data for request/response
    pub correlation_data: Option<Bytes>,
    /// User-defined key-value properties
    pub user_properties: Vec<(String, String)>,
    /// Subscription identifiers
    pub subscription_id: Vec<u32>,
    /// Content type descriptor
    pub content_type: Option<String>,
}

impl PropertyFrame for PublishProperties {
    /// Calculates the encoded length of all properties
    fn encoded_len(&self) -> usize {
        let mut len = 0usize;

        len += property_len!(&self.payload_format_indicator);
        len += property_len!(&self.message_expiry_interval);
        len += property_len!(&self.topic_alias);
        len += property_len!(&self.response_topic);
        len += property_len!(&self.correlation_data);
        len += property_len!(&self.user_properties);
        len += property_len!(&self.subscription_id);
        len += property_len!(&self.content_type);

        len
    }

    /// Encodes all properties into a byte buffer
    fn encode(&self, buf: &mut BytesMut) {
        property_encode!(
            &self.payload_format_indicator,
            Property::PayloadFormatIndicator,
            buf
        );
        property_encode!(
            &self.message_expiry_interval,
            Property::MessageExpiryInterval,
            buf
        );
        property_encode!(&self.topic_alias, Property::TopicAlias, buf);
        property_encode!(&self.response_topic, Property::ResponseTopic, buf);
        property_encode!(&self.correlation_data, Property::CorrelationData, buf);
        property_encode!(&self.user_properties, Property::UserProp, buf);
        property_encode!(&self.subscription_id, Property::SubscriptionIdentifier, buf);
        property_encode!(&self.content_type, Property::ContentType, buf);
    }

    fn decode(buf: &mut Bytes) -> Result<Option<Self>, Error>
    where
        Self: Sized,
    {
        if buf.is_empty() {
            return Ok(None);
        }

        let mut payload_format_indicator: Option<u8> = None;
        let mut message_expiry_interval: Option<Duration> = None;
        let mut topic_alias: Option<u16> = None;
        let mut response_topic: Option<String> = None;
        let mut correlation_data: Option<Bytes> = None;
        let mut user_properties: Vec<(String, String)> = Vec::new();
        let mut subscription_id: Vec<u32> = Vec::new();
        let mut content_type: Option<String> = None;

        while buf.has_remaining() {
            let property: Property = decode_byte(buf)?.try_into()?;
            match property {
                Property::PayloadFormatIndicator => {
                    property_decode!(&mut payload_format_indicator, buf);
                }
                Property::MessageExpiryInterval => {
                    property_decode!(&mut message_expiry_interval, buf);
                }
                Property::TopicAlias => {
                    property_decode!(&mut topic_alias, buf);
                }
                Property::ResponseTopic => {
                    property_decode!(&mut response_topic, buf);
                }
                Property::CorrelationData => {
                    property_decode!(&mut correlation_data, buf);
                }
                Property::UserProp => {
                    property_decode!(&mut user_properties, buf);
                }
                Property::SubscriptionIdentifier => {
                    property_decode!(&mut subscription_id, buf);
                }
                Property::ContentType => {
                    property_decode!(&mut content_type, buf);
                }
                _ => return Err(Error::PropertyMismatch),
            }
        }

        Ok(Some(PublishProperties {
            payload_format_indicator,
            message_expiry_interval,
            topic_alias,
            response_topic,
            correlation_data,
            user_properties,
            subscription_id,
            content_type,
        }))
    }
}

/// Internal header structure for `Publish` packets
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublishHeader {
    /// Common publish header fields
    pub(crate) inner: common::PublishHeader,
    /// MQTT v5 specific properties
    pub(crate) properties: Option<PublishProperties>,
}

impl PublishHeader {
    /// Creates a new `Publish` header
    pub(crate) fn new<T: Into<String>>(
        topic: T,
        packet_id: u16,
        properties: Option<PublishProperties>,
    ) -> Self {
        PublishHeader {
            inner: common::PublishHeader::new(topic, packet_id),
            properties,
        }
    }

    /// Calculates the encoded length of the header
    pub(crate) fn encoded_len(&self, qos: QoS) -> usize {
        let properties_len = self
            .properties
            .as_ref()
            .map(|properties| properties.encoded_len())
            .unwrap_or(0);

        self.inner.encoded_len(qos) + len_bytes(properties_len) + properties_len
    }

    /// Encodes the header into a byte buffer
    pub(crate) fn encode(&self, buf: &mut BytesMut, qos: QoS) -> Result<(), Error> {
        self.inner.encode(buf, qos);

        let properties_len = self
            .properties
            .as_ref()
            .map(|properties| properties.encoded_len())
            .unwrap_or(0) as u32;

        encode_variable_integer(buf, properties_len)?;

        if let Some(properties) = self.properties.as_ref() {
            properties.encode(buf);
        }

        Ok(())
    }

    /// Decodes a header from byte payload
    pub(crate) fn decode(payload: &mut Bytes, qos: QoS) -> Result<Self, Error> {
        let inner = common::PublishHeader::decode(payload, qos)?;

        let properties_len = decode_variable_integer(payload)? as usize;
        if payload.len() < properties_len + len_bytes(properties_len) {
            return Err(Error::MalformedPacket);
        }

        payload.advance(len_bytes(properties_len));
        let mut properties_buf = payload.split_to(properties_len);
        let properties = PublishProperties::decode(&mut properties_buf)?;

        Ok(PublishHeader { inner, properties })
    }
}

/// Represents an MQTT v5 `Publish` packet
///
/// This is the primary structure for message publication in MQTT, supporting:
/// - All QoS levels (0, 1, and 2)
/// - Retained messages
/// - Duplicate delivery detection
/// - Extensive message properties (v5 only)
///
/// # Example
///
/// ```rust
/// use bytes::Bytes;
/// use mqute_codec::protocol::{Flags, QoS};
/// use mqute_codec::protocol::v5::{Publish, PublishProperties};
///
/// // Create a QoS 1 message with properties
/// let properties = PublishProperties {
///     content_type: Some("text/plain".into()),
///     ..Default::default()
/// };
/// let publish = Publish::new(
///     "test/topic",
///     1234,
///     Some(properties.clone()),
///     Bytes::from("message payload"),
///     Flags::new(QoS::AtLeastOnce)
/// );
///
/// assert_eq!(publish.flags(), Flags::new(QoS::AtLeastOnce));
///
/// assert_eq!(publish.packet_id(), Some(1234u16));
///
/// assert_eq!(publish.properties(), Some(properties));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    header: PublishHeader,
    payload: Bytes,
    flags: Flags,
}

impl Publish {
    /// Creates a new `Publish` packet
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - QoS > 0 but packet_id is 0.
    /// - The topic name is invalid according to MQTT topic naming rules.
    pub fn new<T: Into<String>>(
        topic: T,
        packet_id: u16,
        properties: Option<PublishProperties>,
        payload: Bytes,
        flags: Flags,
    ) -> Self {
        if flags.qos != QoS::AtMostOnce && packet_id == 0 {
            panic!("Control packets must contain a non-zero packet identifier at QoS > 0");
        }

        Publish {
            header: PublishHeader::new(topic, packet_id, properties),
            payload,
            flags,
        }
    }

    /// Returns the packet flags
    pub fn flags(&self) -> Flags {
        self.flags
    }

    /// Returns the packet identifier (if QoS > 0)
    pub fn packet_id(&self) -> Option<u16> {
        if self.flags.qos != QoS::AtMostOnce {
            Some(self.header.inner.packet_id)
        } else {
            None
        }
    }

    /// Returns the message topic
    pub fn topic(&self) -> String {
        self.header.inner.topic.clone()
    }

    /// Returns a copy of the properties (if any)
    pub fn properties(&self) -> Option<PublishProperties> {
        self.header.properties.clone()
    }

    /// Returns the message payload
    pub fn payload(&self) -> Bytes {
        self.payload.clone()
    }
}

impl Decode for Publish {
    /// Decodes a `Publish` packet from raw bytes
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::Publish {
            return Err(Error::MalformedPacket);
        }

        let flags = packet.header.flags();
        let header = PublishHeader::decode(&mut packet.payload, flags.qos)?;
        let packet = Publish {
            header,
            payload: packet.payload,
            flags,
        };
        Ok(packet)
    }
}

impl Encode for Publish {
    /// Encodes the `Publish` packet into a byte buffer
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::with_flags(PacketType::Publish, self.flags, self.payload_len());
        header.encode(buf)?;
        self.header.encode(buf, self.flags.qos)?;
        buf.extend_from_slice(&self.payload);
        Ok(())
    }

    /// Calculates the total packet length
    fn payload_len(&self) -> usize {
        self.header.encoded_len(self.flags.qos) + self.payload.len()
    }
}
