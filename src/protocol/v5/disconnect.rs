//! # Disconnect Packet - MQTT v5
//!
//! This module implements the MQTT v5 `Disconnect` packet, which is used to gracefully
//! terminate a connection between client and server. The `Disconnect` packet can include
//! a reason code and optional properties to provide additional context for the disconnection.

use crate::Error;
use crate::codec::util::{decode_byte, decode_variable_integer, encode_variable_integer};
use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::util::len_bytes;
use crate::protocol::v5::property::{
    Property, PropertyFrame, property_decode, property_encode, property_len,
};
use crate::protocol::v5::reason::ReasonCode;
use crate::protocol::{FixedHeader, PacketType};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::time::Duration;

/// Validates reason codes for `Disconnect` packets
///
/// MQTT v5 specifies the following valid reason codes:
/// - 0x00 (Normal Disconnection)
/// - 0x04 (Disconnect With Will Message)
/// - 0x80-0x83 (Various error conditions)
/// - 0x87-0x93 (Protocol and implementation errors)
/// - 0x97-0xA2 (Administrative and policy violations)
fn validate_disconnect_reason_code(code: ReasonCode) -> bool {
    matches!(code.into(), 0 | 4 | 128..=131 | 135 | 137 | 139 | 141..=144 | 147..=162)
}

/// Represents properties of a `Disconnect` packet
///
/// # Example
///
/// ```rust
///
/// use mqute_codec::protocol::v5::DisconnectProperties;
///
/// let properties = DisconnectProperties {
///     reason_string: Some("Reason string".to_string()),
///     server_reference: Some("backup.example.com".to_string()),
///     ..Default::default()
/// };
///
/// ```
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DisconnectProperties {
    /// Duration in seconds until session expires
    pub session_expiry_interval: Option<Duration>,
    /// Human-readable disconnection reason
    pub reason_string: Option<String>,
    /// User-defined key-value properties
    pub user_properties: Vec<(String, String)>,
    /// Alternative server reference (for redirection)
    pub server_reference: Option<String>,
}

impl PropertyFrame for DisconnectProperties {
    /// Calculates the encoded length of the properties
    fn encoded_len(&self) -> usize {
        let mut len = 0usize;

        len += property_len!(&self.session_expiry_interval);
        len += property_len!(&self.reason_string);
        len += property_len!(&self.user_properties);
        len += property_len!(&self.server_reference);

        len
    }

    /// Encodes the properties into a byte buffer
    fn encode(&self, buf: &mut BytesMut) {
        property_encode!(
            &self.session_expiry_interval,
            Property::SessionExpiryInterval,
            buf
        );

        property_encode!(&self.reason_string, Property::ReasonString, buf);
        property_encode!(&self.user_properties, Property::UserProp, buf);
        property_encode!(&self.server_reference, Property::ServerReference, buf);
    }

    /// Decodes properties from a byte buffer
    fn decode(buf: &mut Bytes) -> Result<Option<Self>, Error>
    where
        Self: Sized,
    {
        if buf.is_empty() {
            return Ok(None);
        }
        let mut session_expiry_interval: Option<Duration> = None;
        let mut reason_string: Option<String> = None;
        let mut user_properties: Vec<(String, String)> = Vec::new();
        let mut server_reference: Option<String> = None;

        while buf.has_remaining() {
            let property: Property = decode_byte(buf)?.try_into()?;
            match property {
                Property::SessionExpiryInterval => {
                    property_decode!(&mut session_expiry_interval, buf);
                }
                Property::ReasonString => {
                    property_decode!(&mut reason_string, buf);
                }
                Property::UserProp => {
                    property_decode!(&mut user_properties, buf);
                }
                Property::ServerReference => {
                    property_decode!(&mut server_reference, buf);
                }
                _ => return Err(Error::PropertyMismatch),
            }
        }

        Ok(Some(DisconnectProperties {
            session_expiry_interval,
            reason_string,
            user_properties,
            server_reference,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DisconnectHeader {
    code: ReasonCode,
    properties: Option<DisconnectProperties>,
}

impl DisconnectHeader {
    pub(crate) fn new(code: ReasonCode, properties: Option<DisconnectProperties>) -> Self {
        if !validate_disconnect_reason_code(code) {
            panic!("Invalid reason code {code}")
        }
        DisconnectHeader { code, properties }
    }

    pub(crate) fn encoded_len(&self) -> usize {
        if self.code == ReasonCode::NormalDisconnection && self.properties.is_none() {
            return 0;
        }

        let properties_len = self
            .properties
            .as_ref()
            .map(|properties| properties.encoded_len())
            .unwrap_or(0);

        1 + len_bytes(properties_len) + properties_len
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        // The reason code and property can be omitted if the code is 0x00 and there are no properties
        if self.code == ReasonCode::NormalDisconnection && self.properties.is_none() {
            return Ok(());
        }

        buf.put_u8(self.code.into());

        let properties_len = self
            .properties
            .as_ref()
            .map(|properties| properties.encoded_len())
            .unwrap_or(0) as u32;

        // Encode properties len
        encode_variable_integer(buf, properties_len)?;

        // Encode properties
        if let Some(properties) = self.properties.as_ref() {
            properties.encode(buf);
        }

        Ok(())
    }

    pub(crate) fn decode(payload: &mut Bytes) -> Result<Self, Error> {
        if payload.is_empty() {
            return Ok(DisconnectHeader {
                code: ReasonCode::NormalDisconnection,
                properties: None,
            });
        }

        let code: ReasonCode = decode_byte(payload)?.try_into().map(|code| {
            if code == ReasonCode::Success {
                ReasonCode::NormalDisconnection
            } else {
                code
            }
        })?;

        if !validate_disconnect_reason_code(code) {
            return Err(Error::InvalidReasonCode(code.into()));
        }

        let properties_len = decode_variable_integer(payload)? as usize;
        if payload.len() < properties_len + len_bytes(properties_len) {
            return Err(Error::MalformedPacket);
        }

        // Skip variable byte
        payload.advance(len_bytes(properties_len));

        let mut properties_buf = payload.split_to(properties_len);

        // Deserialize properties
        let properties = DisconnectProperties::decode(&mut properties_buf)?;
        Ok(DisconnectHeader { code, properties })
    }
}

/// Represents an MQTT v5 `Disconnect` packet.
///
/// The `Disconnect` packet is the final MQTT Control Packet sent from the Client
/// or the Server. It indicates the reason why the Network Connection is being closed
///
/// # Example
///
/// ```rust
/// use mqute_codec::protocol::v5::{Disconnect, DisconnectProperties, ReasonCode};
///
/// let properties = DisconnectProperties {
///     reason_string: Some("Reason string".to_string()),
///     server_reference: Some("backup.example.com".to_string()),
///     ..Default::default()
/// };
///
/// let disconnect = Disconnect::new(ReasonCode::Success, Some(properties.clone()));
/// assert_eq!(disconnect.properties(), Some(properties));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disconnect {
    header: DisconnectHeader,
}

impl Disconnect {
    /// Creates a new `Disconnect` packet
    pub fn new(code: ReasonCode, properties: Option<DisconnectProperties>) -> Self {
        Disconnect {
            header: DisconnectHeader::new(code, properties),
        }
    }

    /// Returns the reason code
    pub fn code(&self) -> ReasonCode {
        self.header.code
    }

    /// Returns a copy of the properties (if any)
    pub fn properties(&self) -> Option<DisconnectProperties> {
        self.header.properties.clone()
    }
}

impl Encode for Disconnect {
    /// Encodes the `Disconnect` packet into a byte buffer
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::Disconnect, self.payload_len());
        header.encode(buf)?;

        self.header.encode(buf)
    }

    /// Calculates the payload length
    fn payload_len(&self) -> usize {
        self.header.encoded_len()
    }
}

impl Decode for Disconnect {
    /// Decodes a `Disconnect` packet from raw bytes
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::Disconnect
            || !packet.header.flags().is_default()
        {
            return Err(Error::MalformedPacket);
        }

        let header = DisconnectHeader::decode(&mut packet.payload)?;
        Ok(Disconnect { header })
    }
}
