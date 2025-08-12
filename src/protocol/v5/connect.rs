//! # Connect Packet V5
//!
//! This module provides the complete implementation of the MQTT v5 Connect packet,
//! including its properties, will message handling, and authentication support.
//! The Connect packet is the first packet sent by a client to initiate a connection
//! with an MQTT broker.

use super::property::{Property, PropertyFrame, property_len};
use super::property::{property_decode, property_decode_non_zero, property_encode};
use crate::Error;
use crate::codec::util::{
    decode_byte, decode_bytes, decode_string, decode_variable_integer, encode_bytes, encode_string,
    encode_variable_integer,
};
use crate::protocol::common::{ConnectFrame, WillFrame};
use crate::protocol::common::{ConnectHeader, connect};
use crate::protocol::util::len_bytes;
use crate::protocol::{Credentials, Protocol, QoS};
use bit_field::BitField;
use bytes::{Buf, Bytes, BytesMut};
use std::ops::RangeInclusive;
use std::time::Duration;

/// Bit flag positions for Connect packet flags
const WILL_FLAG: usize = 2;
const WILL_QOS: RangeInclusive<usize> = 3..=4;
const WILL_RETAIN: usize = 5;

/// Represents the properties of a Connect packet in MQTT v5.
///
/// These properties provide extended functionality beyond the basic connection
/// parameters, including session management, flow control, and authentication.
///
/// # Example
///
/// ```rust
/// use mqute_codec::protocol::v5::ConnectProperties;
/// use std::time::Duration;
///
/// let connect_properties = ConnectProperties {
///     session_expiry_interval: Some(Duration::from_secs(3600)),
///     maximum_packet_size: Some(4096u32),
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConnectProperties {
    /// Duration in seconds after which the session expires
    pub session_expiry_interval: Option<Duration>,
    /// Maximum number of QoS 1 and 2 publishes the client will process
    pub receive_maximum: Option<u16>,
    /// Maximum packet size the client will accept
    pub maximum_packet_size: Option<u32>,
    /// Highest value the client will accept as a topic alias
    pub topic_alias_maximum: Option<u16>,
    /// Whether the server should include response information
    pub request_response_info: Option<bool>,
    /// Whether the server should include reason strings
    pub request_problem_info: Option<bool>,
    /// User-defined key-value properties
    pub user_properties: Vec<(String, String)>,
    /// Authentication method name
    pub auth_method: Option<String>,
    /// Authentication data
    pub auth_data: Option<Bytes>,
}

impl PropertyFrame for ConnectProperties {
    /// Calculates the encoded length of the properties
    fn encoded_len(&self) -> usize {
        let mut len = 0;

        len += property_len!(&self.session_expiry_interval);
        len += property_len!(&self.receive_maximum);
        len += property_len!(&self.maximum_packet_size);
        len += property_len!(&self.topic_alias_maximum);
        len += property_len!(&self.request_response_info);
        len += property_len!(&self.request_problem_info);
        len += property_len!(&self.user_properties);
        len += property_len!(&self.auth_method);
        len += property_len!(&self.auth_data);

        len
    }

    /// Encodes the properties into a byte buffer
    fn encode(&self, buf: &mut BytesMut) {
        property_encode!(
            &self.session_expiry_interval,
            Property::SessionExpiryInterval,
            buf
        );
        property_encode!(&self.receive_maximum, Property::ReceiveMaximum, buf);
        property_encode!(&self.maximum_packet_size, Property::MaximumPacketSize, buf);
        property_encode!(&self.topic_alias_maximum, Property::TopicAliasMaximum, buf);
        property_encode!(
            &self.request_response_info,
            Property::RequestResponseInformation,
            buf
        );
        property_encode!(
            &self.request_problem_info,
            Property::RequestProblemInformation,
            buf
        );
        property_encode!(&self.user_properties, Property::UserProp, buf);
        property_encode!(&self.auth_method, Property::AuthenticationMethod, buf);
        property_encode!(&self.auth_data, Property::AuthenticationData, buf);
    }

    /// Decodes properties from a byte buffer
    fn decode(buf: &mut Bytes) -> Result<Option<Self>, Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        let mut properties = ConnectProperties::default();

        while buf.has_remaining() {
            let property: Property = decode_byte(buf)?.try_into()?;
            match property {
                Property::SessionExpiryInterval => {
                    property_decode!(&mut properties.session_expiry_interval, buf);
                }
                Property::ReceiveMaximum => {
                    property_decode_non_zero!(&mut properties.receive_maximum, buf);
                }
                Property::MaximumPacketSize => {
                    property_decode_non_zero!(&mut properties.maximum_packet_size, buf);
                }
                Property::TopicAliasMaximum => {
                    property_decode!(&mut properties.topic_alias_maximum, buf);
                }
                Property::RequestResponseInformation => {
                    property_decode!(&mut properties.request_response_info, buf);
                }
                Property::RequestProblemInformation => {
                    property_decode!(&mut properties.request_problem_info, buf);
                }
                Property::UserProp => {
                    property_decode!(&mut properties.user_properties, buf);
                }
                Property::AuthenticationMethod => {
                    property_decode!(&mut properties.auth_method, buf);
                }
                Property::AuthenticationData => {
                    property_decode!(&mut properties.auth_data, buf);
                }
                _ => return Err(Error::PropertyMismatch),
            };
        }

        if properties.auth_data.is_some() && properties.auth_method.is_none() {
            return Err(Error::ProtocolError);
        }

        Ok(Some(properties))
    }
}

impl ConnectFrame for ConnectHeader<ConnectProperties> {
    /// Calculates the encoded length of the Connect header
    fn encoded_len(&self) -> usize {
        let properties_len = self
            .properties
            .as_ref()
            .map(|properties| properties.encoded_len())
            .unwrap_or(0);
        properties_len + len_bytes(properties_len) + self.primary_encoded_len()
    }

    /// Encodes the Connect header into a byte buffer
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        self.primary_encode(buf);

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

    /// Decodes a Connect header from a byte buffer
    fn decode(buf: &mut Bytes) -> Result<Self, Error> {
        let mut header = Self::primary_decode(buf)?;

        let properties_len = decode_variable_integer(buf)? as usize;
        if buf.len() < properties_len + len_bytes(properties_len) {
            return Err(Error::MalformedPacket);
        }

        // Skip variable byte
        buf.advance(len_bytes(properties_len));

        let mut properties_buf = buf.split_to(properties_len);

        // Deserialize properties
        header.properties = ConnectProperties::decode(&mut properties_buf)?;

        Ok(header)
    }
}

/// Represents the properties of a Will message in MQTT v5.
///
/// These properties provide extended functionality for the last will and testament
/// message, including delivery timing, content format, and correlation data.
/// # Example
///
/// ```rust
/// use std::time::Duration;
/// use mqute_codec::protocol::v5::WillProperties;
///
/// let will_properties = WillProperties {
///     delay_interval: Some(Duration::from_secs(10)),
///     content_type: Some("json".to_string()),
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WillProperties {
    /// Delay before sending the Will message after connection loss
    pub delay_interval: Option<Duration>,
    /// Format of the Will message payload (0=bytes, 1=UTF-8)
    pub payload_format_indicator: Option<u8>,
    /// Lifetime of the Will message in seconds
    pub message_expiry_interval: Option<Duration>,
    /// Content type descriptor (MIME type)
    pub content_type: Option<String>,
    /// Topic name for the response message
    pub response_topic: Option<String>,
    /// Correlation data for the response message
    pub correlation_data: Option<Bytes>,
    /// User-defined key-value properties
    pub user_properties: Vec<(String, String)>,
}

impl PropertyFrame for WillProperties {
    /// Calculates the encoded length of the Will properties
    fn encoded_len(&self) -> usize {
        let mut len = 0;

        len += property_len!(&self.delay_interval);
        len += property_len!(&self.payload_format_indicator);
        len += property_len!(&self.message_expiry_interval);
        len += property_len!(&self.content_type);
        len += property_len!(&self.response_topic);
        len += property_len!(&self.correlation_data);
        len += property_len!(&self.user_properties);

        len
    }

    /// Encodes the Will properties into a byte buffer
    fn encode(&self, buf: &mut BytesMut) {
        property_encode!(&self.delay_interval, Property::WillDelayInterval, buf);
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
        property_encode!(&self.content_type, Property::ContentType, buf);
        property_encode!(&self.response_topic, Property::ResponseTopic, buf);
        property_encode!(&self.correlation_data, Property::CorrelationData, buf);
        property_encode!(&self.user_properties, Property::UserProp, buf);
    }

    /// Decodes Will properties from a byte buffer
    fn decode(buf: &mut Bytes) -> Result<Option<Self>, Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        let mut properties = WillProperties::default();

        while buf.has_remaining() {
            let property: Property = decode_byte(buf)?.try_into()?;
            match property {
                Property::WillDelayInterval => {
                    property_decode!(&mut properties.delay_interval, buf);
                }
                Property::PayloadFormatIndicator => {
                    property_decode!(&mut properties.payload_format_indicator, buf);
                    if let Some(value) = properties.payload_format_indicator {
                        if value != 0 && value != 1 {
                            return Err(Error::ProtocolError);
                        }
                    }
                }
                Property::MessageExpiryInterval => {
                    property_decode!(&mut properties.message_expiry_interval, buf);
                }
                Property::ContentType => {
                    property_decode!(&mut properties.content_type, buf);
                }
                Property::ResponseTopic => {
                    property_decode!(&mut properties.response_topic, buf);
                }
                Property::CorrelationData => {
                    property_decode!(&mut properties.correlation_data, buf);
                }
                Property::UserProp => {
                    property_decode!(&mut properties.user_properties, buf);
                }
                _ => return Err(Error::PropertyMismatch),
            }
        }

        Ok(Some(properties))
    }
}

/// Represents a Will message in MQTT v5.
///
/// The Will message is published by the broker when the client disconnects
/// unexpectedly. It includes the message content, delivery options, and properties.
///
/// # Example
///
/// ```rust
/// use mqute_codec::protocol::v5::Will;
/// use bytes::Bytes;
/// use mqute_codec::protocol::QoS;
///
/// let will = Will::new(None, "tpoic", Bytes::new(), QoS::ExactlyOnce, false);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Will {
    /// Will message properties
    pub properties: Option<WillProperties>,
    /// Topic name to publish the Will message to
    pub topic: String,
    /// Will message payload
    pub payload: Bytes,
    /// Quality of Service level for the Will message
    pub qos: QoS,
    /// Whether the Will message should be retained
    pub retain: bool,
}

impl Will {
    /// Creates a new `Will` packet
    pub fn new<T: Into<String>>(
        properties: Option<WillProperties>,
        topic: T,
        payload: Bytes,
        qos: QoS,
        retain: bool,
    ) -> Will {
        Will {
            properties,
            topic: topic.into(),
            payload,
            qos,
            retain,
        }
    }
}

impl WillFrame for Will {
    /// Calculates the encoded length of the Will message
    fn encoded_len(&self) -> usize {
        let properties_len = self
            .properties
            .as_ref()
            .map(|properties| properties.encoded_len())
            .unwrap_or(0);

        2 + self.topic.len() + 2 + self.payload.len() + len_bytes(properties_len) + properties_len
    }

    /// Updates the Connect packet flags based on Will message settings
    fn update_flags(&self, flags: &mut u8) {
        // Update the 'Will' flag
        flags.set_bit(WILL_FLAG, true);

        // Update 'Qos' flags
        flags.set_bits(WILL_QOS, self.qos as u8);

        // Update the 'Will Retain' flag
        flags.set_bit(WILL_RETAIN, self.retain);
    }

    /// Encodes the Will message into a byte buffer
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let properties_len = self
            .properties
            .as_ref()
            .map(|properties| properties.encoded_len())
            .unwrap_or(0) as u32;

        encode_variable_integer(buf, properties_len)?;

        if let Some(properties) = self.properties.as_ref() {
            properties.encode(buf);
        }

        encode_string(buf, &self.topic);
        encode_bytes(buf, &self.payload);
        Ok(())
    }

    /// Decodes a Will message from a byte buffer
    fn decode(buf: &mut Bytes, flags: u8) -> Result<Option<Self>, Error> {
        if !flags.get_bit(WILL_FLAG) {
            // No 'Will'
            return Ok(None);
        }

        let properties_len = decode_variable_integer(buf)? as usize;
        if buf.len() < properties_len + len_bytes(properties_len) {
            return Err(Error::MalformedPacket);
        }

        // Skip properties len
        buf.advance(len_bytes(properties_len));
        let mut properties_buf = buf.split_to(properties_len);
        let properties = WillProperties::decode(&mut properties_buf)?;
        let qos = flags.get_bits(WILL_QOS).try_into()?;
        let retain = flags.get_bit(WILL_RETAIN);

        let topic = decode_string(buf)?;
        let payload = decode_bytes(buf)?;

        Ok(Some(Will {
            properties,
            topic,
            payload,
            qos,
            retain,
        }))
    }
}

// Defines the `Connect` packet for MQTT V5
connect!(Connect<ConnectProperties, Will>, Protocol::V5);

impl Connect {
    /// Creates a new Connect packet with properties
    ///
    /// # Panics
    ///
    /// Panics if the value of the "keep alive" parameter exceeds 65535
    pub fn with_properties<S: Into<String>>(
        client_id: S,
        auth: Option<Credentials>,
        will: Option<Will>,
        properties: ConnectProperties,
        keep_alive: Duration,
        clean_session: bool,
    ) -> Self {
        Self::from_scratch(
            client_id,
            auth,
            will,
            Some(properties),
            keep_alive,
            clean_session,
        )
    }

    /// Returns the Connect properties if present
    pub fn properties(&self) -> Option<ConnectProperties> {
        self.header.properties.clone()
    }
}
