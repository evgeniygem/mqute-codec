//! # ConnAck Packet V5
//!
//! This module defines the `ConnAck` packet, which is sent by the server in response to a
//! `Connect` packet from a client in the MQTT v5 protocol. The `ConnAck` packet indicates
//! the result of the connection attempt and includes session status and optional properties
//! for session configuration and server capabilities.

use super::property::{
    property_decode, property_decode_non_zero, property_encode, property_len, Property,
    PropertyFrame,
};
use crate::codec::util::{decode_byte, decode_variable_integer, encode_variable_integer};
use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::util::len_bytes;
use crate::protocol::v5::reason::ReasonCode;
use crate::protocol::{FixedHeader, PacketType, QoS};
use crate::Error;
use bit_field::BitField;
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Represents the properties of the `ConnAck` packet.
///
/// These properties provide additional connection-related information from the server
/// to the client, including session configuration and server capabilities.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConnAckProperties {
    /// Duration in seconds the session will be kept after disconnection
    pub session_expiry_interval: Option<u32>,
    /// Maximum number of QoS 1 and 2 messages the server will process concurrently
    pub receive_maximum: Option<u16>,
    /// Maximum QoS level the server supports
    pub maximum_qos: Option<QoS>,
    /// Whether the server supports retained messages
    pub retain_available: Option<bool>,
    /// Maximum packet size the server will accept
    pub maximum_packet_size: Option<u32>,
    /// Client identifier assigned by the server
    pub assigned_client_id: Option<String>,
    /// Maximum number of topic aliases the server will accept
    pub topic_alias_maximum: Option<u16>,
    /// Human-readable reason string for the connection result
    pub reason: Option<String>,
    /// User-defined properties for extensibility
    pub user_properties: Vec<(String, String)>,
    /// Whether wildcard subscriptions are supported
    pub wildcard_subscription_available: Option<bool>,
    /// Whether subscription identifiers are supported
    pub subscription_id_available: Option<bool>,
    /// Whether shared subscriptions are supported
    pub shared_subscription_available: Option<bool>,
    /// Keep alive time suggested by the server
    pub server_keep_alive: Option<u16>,
    /// Response information for authentication
    pub response_info: Option<String>,
    /// Server reference for redirection
    pub server_reference: Option<String>,
    /// Authentication method
    pub auth_method: Option<String>,
    /// Authentication data
    pub auth_data: Option<Bytes>,
}

impl PropertyFrame for ConnAckProperties {
    /// Returns the encoded length of the `ConnAckProperties`.
    fn encoded_len(&self) -> usize {
        let mut len = 0;

        len += property_len!(&self.session_expiry_interval);
        len += property_len!(&self.receive_maximum);
        len += property_len!(&self.maximum_qos);
        len += property_len!(&self.retain_available);
        len += property_len!(&self.maximum_packet_size);
        len += property_len!(&self.assigned_client_id);
        len += property_len!(&self.topic_alias_maximum);
        len += property_len!(&self.reason);
        len += property_len!(&self.user_properties);
        len += property_len!(&self.wildcard_subscription_available);
        len += property_len!(&self.subscription_id_available);
        len += property_len!(&self.shared_subscription_available);
        len += property_len!(&self.server_keep_alive);
        len += property_len!(&self.response_info);
        len += property_len!(&self.server_reference);
        len += property_len!(&self.auth_method);
        len += property_len!(&self.auth_data);

        len
    }

    /// Encodes the `ConnAckProperties` into a byte buffer.
    fn encode(&self, buf: &mut BytesMut) {
        property_encode!(
            &self.session_expiry_interval,
            Property::SessionExpiryInterval,
            buf
        );
        property_encode!(&self.receive_maximum, Property::ReceiveMaximum, buf);
        property_encode!(&self.maximum_qos, Property::MaximumQoS, buf);
        property_encode!(&self.retain_available, Property::RetainAvailable, buf);
        property_encode!(&self.maximum_packet_size, Property::MaximumPacketSize, buf);
        property_encode!(
            &self.assigned_client_id,
            Property::AssignedClientIdentifier,
            buf
        );
        property_encode!(&self.topic_alias_maximum, Property::TopicAliasMaximum, buf);
        property_encode!(&self.reason, Property::ReasonString, buf);
        property_encode!(&self.user_properties, Property::UserProperty, buf);
        property_encode!(
            &self.wildcard_subscription_available,
            Property::WildcardSubscriptionAvailable,
            buf
        );
        property_encode!(
            &self.subscription_id_available,
            Property::SubscriptionIdentifierAvailable,
            buf
        );
        property_encode!(
            &self.shared_subscription_available,
            Property::SharedSubscriptionAvailable,
            buf
        );
        property_encode!(&self.server_keep_alive, Property::ServerKeepAlive, buf);
        property_encode!(&self.response_info, Property::ResponseInformation, buf);
        property_encode!(&self.server_reference, Property::ServerReference, buf);
        property_encode!(&self.auth_method, Property::AuthenticationMethod, buf);
        property_encode!(&self.auth_data, Property::AuthenticationData, buf);
    }

    /// Decodes the `ConnAckProperties` from a byte buffer.
    fn decode(buf: &mut Bytes) -> Result<Option<Self>, Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        let mut properties = ConnAckProperties::default();

        while buf.has_remaining() {
            let property: Property = decode_byte(buf)?.try_into()?;
            match property {
                Property::SessionExpiryInterval => {
                    property_decode!(&mut properties.session_expiry_interval, buf);
                }
                Property::ReceiveMaximum => {
                    property_decode_non_zero!(&mut properties.receive_maximum, buf);
                }
                Property::MaximumQoS => {
                    property_decode!(&mut properties.maximum_qos, buf);
                }
                Property::RetainAvailable => {
                    property_decode!(&mut properties.retain_available, buf);
                }
                Property::MaximumPacketSize => {
                    property_decode_non_zero!(&mut properties.maximum_packet_size, buf);
                }
                Property::AssignedClientIdentifier => {
                    property_decode!(&mut properties.assigned_client_id, buf);
                }
                Property::TopicAliasMaximum => {
                    property_decode!(&mut properties.topic_alias_maximum, buf);
                }
                Property::ReasonString => {
                    property_decode!(&mut properties.reason, buf);
                }
                Property::UserProperty => {
                    property_decode!(&mut properties.user_properties, buf);
                }
                Property::WildcardSubscriptionAvailable => {
                    property_decode!(&mut properties.wildcard_subscription_available, buf);
                }
                Property::SubscriptionIdentifierAvailable => {
                    property_decode!(&mut properties.subscription_id_available, buf);
                }
                Property::SharedSubscriptionAvailable => {
                    property_decode!(&mut properties.shared_subscription_available, buf);
                }
                Property::ServerKeepAlive => {
                    property_decode!(&mut properties.server_keep_alive, buf);
                }
                Property::ResponseInformation => {
                    property_decode!(&mut properties.response_info, buf);
                }
                Property::ServerReference => {
                    property_decode!(&mut properties.server_reference, buf);
                }
                Property::AuthenticationMethod => {
                    property_decode!(&mut properties.auth_method, buf);
                }
                Property::AuthenticationData => {
                    property_decode!(&mut properties.auth_data, buf);
                }
                _ => return Err(Error::PropertyMismatch),
            }
        }

        Ok(Some(properties))
    }
}

/// Validates that the reason code is appropriate for a ConnAck packet
fn validate_connack_reason_code(code: ReasonCode) -> bool {
    matches!(code.into(), 0 | 128..=138 | 140 | 144 | 149 | 151 | 153..=157 | 159)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnAckHeader {
    code: ReasonCode,
    session_present: bool,
    properties: Option<ConnAckProperties>,
}

impl ConnAckHeader {
    fn new(code: ReasonCode, session_present: bool, properties: Option<ConnAckProperties>) -> Self {
        if !validate_connack_reason_code(code) {
            panic!("Invalid reason code {code}");
        }
        ConnAckHeader {
            code,
            session_present,
            properties,
        }
    }

    fn encoded_len(&self) -> usize {
        let properties_len = self
            .properties
            .as_ref()
            .map(|properties| properties.encoded_len())
            .unwrap_or(0);
        1 + 1 + len_bytes(properties_len) + properties_len
    }

    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let mut flags = 0u8;
        flags.set_bit(0, self.session_present);

        // Write a session present flag
        buf.put_u8(flags);

        // Write a connect return code
        buf.put_u8(self.code.into());

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

    fn decode(payload: &mut Bytes) -> Result<Self, Error> {
        let conn_ack_flag = decode_byte(payload)?;
        let code = decode_byte(payload)?.try_into()?;

        if !validate_connack_reason_code(code) {
            return Err(Error::InvalidReasonCode(code.into()));
        }

        let session_present = conn_ack_flag.get_bit(0);

        let properties_len = decode_variable_integer(payload)? as usize;
        if payload.len() < properties_len + len_bytes(properties_len) {
            return Err(Error::MalformedPacket);
        }

        // Skip properties len
        payload.advance(len_bytes(properties_len));

        let mut frame = payload.split_to(properties_len);
        let properties = ConnAckProperties::decode(&mut frame)?;

        Ok(ConnAckHeader {
            code,
            session_present,
            properties,
        })
    }
}

/// Represents an MQTT `CONNACK` packet.
///
/// The `ConnAck` packet is sent by the server in response to a `Connect` packet
/// from a client. It indicates whether the connection was accepted and provides
/// session status and optional properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnAck {
    header: ConnAckHeader,
}

impl ConnAck {
    /// Creates a new `ConnAck` packet.
    ///
    /// # Example
    ///
    /// ```rust
    /// use mqute_codec::protocol::v5::{ConnAck, ConnAckProperties, ReasonCode};
    ///
    /// let properties = ConnAckProperties {
    ///     session_expiry_interval: Some(3600),
    ///     receive_maximum: Some(10),
    ///     ..Default::default()
    /// };
    /// let connack = ConnAck::new(
    ///     ReasonCode::Success,
    ///     true,
    ///     Some(properties)
    /// );
    /// assert_eq!(connack.code(), ReasonCode::Success);
    /// assert!(connack.session_present());
    /// ```
    pub fn new(
        code: ReasonCode,
        session_present: bool,
        properties: Option<ConnAckProperties>,
    ) -> Self {
        ConnAck {
            header: ConnAckHeader::new(code, session_present, properties),
        }
    }

    /// Returns the reason code indicating the connection result.
    ///
    /// # Example
    ///
    /// ```rust
    /// use mqute_codec::protocol::v5::{ConnAck, ReasonCode};
    ///
    /// let connack = ConnAck::new(ReasonCode::Success, false, None);
    /// assert_eq!(connack.code(), ReasonCode::Success);
    /// ```
    pub fn code(&self) -> ReasonCode {
        self.header.code
    }

    /// Returns whether the server has a previous session for this client.
    ///
    /// # Example
    ///
    /// ```rust
    /// use mqute_codec::protocol::v5::ConnAck;
    /// use mqute_codec::protocol::v5::ReasonCode;
    ///
    /// let connack = ConnAck::new(ReasonCode::Success, true, None);
    /// assert!(connack.session_present());
    /// ```
    pub fn session_present(&self) -> bool {
        self.header.session_present
    }

    /// Returns the optional properties of the `ConnAck` packet.
    ///
    /// # Example
    ///
    /// ```rust
    /// use mqute_codec::protocol::v5::{ConnAck, ConnAckProperties, ReasonCode};
    ///
    /// let properties = ConnAckProperties {
    ///     session_expiry_interval: Some(3600),
    ///     ..Default::default()
    /// };
    /// let connack = ConnAck::new(ReasonCode::Success, false, Some(properties.clone()));
    /// assert_eq!(connack.properties(), Some(properties));
    /// ```
    pub fn properties(&self) -> Option<ConnAckProperties> {
        self.header.properties.clone()
    }
}

impl Encode for ConnAck {
    /// Encodes the `ConnAck` packet into a byte buffer.
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::ConnAck, self.payload_len());
        header.encode(buf)?;
        self.header.encode(buf)
    }

    /// Returns the length of the `ConnAck` packet payload.
    fn payload_len(&self) -> usize {
        self.header.encoded_len()
    }
}

impl Decode for ConnAck {
    /// Decodes a `ConnAck` packet from a raw MQTT packet.
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::ConnAck || !packet.header.flags().is_default()
        {
            return Err(Error::MalformedPacket);
        }

        let header = ConnAckHeader::decode(&mut packet.payload)?;
        Ok(ConnAck { header })
    }
}
