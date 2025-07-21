//! # Auth Packet V5
//!
//! This module defines the `Auth` packet, which is used in the MQTT v5 protocol for enhanced
//! authentication and re-authentication. The `Auth` packet includes a reason code and optional
//! properties for authentication data, method, and user-defined properties.

use crate::codec::util::{decode_byte, decode_variable_integer, encode_variable_integer};
use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::util::len_bytes;
use crate::protocol::v5::property::{
    property_decode, property_encode, property_len, Property, PropertyFrame,
};
use crate::protocol::v5::reason::ReasonCode;
use crate::protocol::{FixedHeader, PacketType};
use crate::Error;
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Validates the reason code for the `Auth` packet.
///
/// The `Auth` packet supports only specific reason codes: `Success` (0),
/// `ContinueAuthentication` (24), and `ReAuthenticate` (25).
fn validate_auth_reason_code(code: ReasonCode) -> bool {
    matches!(code.into(), 0 | 24 | 25)
}

/// Represents the properties of the `Auth` packet.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AuthProperties {
    /// The authentication method.
    pub auth_method: Option<String>,

    /// The authentication data.
    pub auth_data: Option<Bytes>,

    /// The reason string for the authentication.
    pub reason_string: Option<String>,

    /// User-defined properties.
    pub user_properties: Vec<(String, String)>,
}

impl PropertyFrame for AuthProperties {
    /// Returns the encoded length of the `AuthProperties`.
    fn encoded_len(&self) -> usize {
        let mut len = 0usize;

        len += property_len!(&self.auth_method);
        len += property_len!(&self.auth_data);
        len += property_len!(&self.reason_string);
        len += property_len!(&self.user_properties);

        len
    }

    /// Encodes the `AuthProperties` into a byte buffer.
    fn encode(&self, buf: &mut BytesMut) {
        property_encode!(&self.auth_method, Property::AuthenticationMethod, buf);
        property_encode!(&self.auth_data, Property::AuthenticationData, buf);
        property_encode!(&self.reason_string, Property::ReasonString, buf);
        property_encode!(&self.user_properties, Property::UserProp, buf);
    }

    /// Decodes the `AuthProperties` from a byte buffer.
    fn decode(buf: &mut Bytes) -> Result<Option<Self>, Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        let mut properties = AuthProperties::default();

        while buf.has_remaining() {
            let property: Property = decode_byte(buf)?.try_into()?;
            match property {
                Property::AuthenticationMethod => {
                    property_decode!(&mut properties.auth_method, buf);
                }
                Property::AuthenticationData => {
                    property_decode!(&mut properties.auth_data, buf);
                }
                Property::ReasonString => {
                    property_decode!(&mut properties.reason_string, buf);
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

/// Represents the header of the `Auth` packet.
///
/// The `AuthHeader` struct includes the reason code and optional properties for the `Auth` packet.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthHeader {
    /// The reason code for the `Auth` packet.
    code: ReasonCode,

    /// Optional properties for the `Auth` packet.
    properties: Option<AuthProperties>,
}

impl AuthHeader {
    /// Creates a new `AuthHeader` instance.
    ///
    /// # Panics
    ///
    /// Panics if the reason code is invalid.
    pub(crate) fn new(code: ReasonCode, properties: Option<AuthProperties>) -> Self {
        if !validate_auth_reason_code(code) {
            panic!("Invalid reason code");
        }
        AuthHeader { code, properties }
    }

    /// Returns the encoded length of the `AuthHeader`.
    ///
    /// If the reason code is `Success` and there are no properties, the length is 0.
    pub(crate) fn encoded_len(&self) -> usize {
        if self.code == ReasonCode::Success && self.properties.is_none() {
            return 0;
        }

        let properties_len = self
            .properties
            .as_ref()
            .map(|properties| properties.encoded_len())
            .unwrap_or(0);

        1 + len_bytes(properties_len) + properties_len
    }

    /// Encodes the `AuthHeader` into a byte buffer.
    pub(crate) fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        // The reason code and properties can be omitted if the code is 0x00 and there are no properties
        if self.code == ReasonCode::Success && self.properties.is_none() {
            return Ok(());
        }

        buf.put_u8(self.code.into());

        let properties_len = self
            .properties
            .as_ref()
            .map(|properties| properties.encoded_len())
            .unwrap_or(0) as u32;

        // Encode properties length
        encode_variable_integer(buf, properties_len)?;

        // Encode properties
        if let Some(properties) = self.properties.as_ref() {
            properties.encode(buf);
        }

        Ok(())
    }

    /// Decodes the `AuthHeader` from a byte buffer.
    pub(crate) fn decode(payload: &mut Bytes) -> Result<Self, Error> {
        if payload.is_empty() {
            return Ok(AuthHeader {
                code: ReasonCode::Success,
                properties: None,
            });
        }

        let code: ReasonCode = decode_byte(payload)?.try_into()?;
        if !validate_auth_reason_code(code) {
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
        let properties = AuthProperties::decode(&mut properties_buf)?;
        Ok(AuthHeader { code, properties })
    }
}

/// Represents an MQTT `AUTH` packet.
///
/// The `Auth` packet is used in the MQTT v5 protocol for enhanced authentication and
/// re-authentication.
///
/// It includes a reason code and optional properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    /// The header of the `Auth` packet, including the reason code and optional properties.
    header: AuthHeader,
}

impl Auth {
    /// Creates a new `Auth` packet.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bytes::Bytes;
    /// use mqute_codec::protocol::v5::{Auth, AuthProperties, ReasonCode};
    ///
    /// let properties = AuthProperties {
    ///     auth_method: Some("method".to_string()),
    ///     auth_data: Some(Bytes::from("data")),
    ///     reason_string: Some("reason".to_string()),
    ///     user_properties: vec![("key".to_string(), "value".to_string())],
    /// };
    /// let auth = Auth::new(ReasonCode::ContinueAuthentication, Some(properties));
    /// assert_eq!(auth.code(), ReasonCode::ContinueAuthentication);
    /// ```
    pub fn new(code: ReasonCode, properties: Option<AuthProperties>) -> Self {
        Auth {
            header: AuthHeader::new(code, properties),
        }
    }

    /// Returns the reason code of the `Auth` packet.
    ///
    /// # Example
    ///
    /// ```rust
    /// use mqute_codec::protocol::v5::{Auth, ReasonCode};
    ///
    /// let auth = Auth::new(ReasonCode::ContinueAuthentication, None);
    /// assert_eq!(auth.code(), ReasonCode::ContinueAuthentication);
    /// ```
    pub fn code(&self) -> ReasonCode {
        self.header.code
    }

    /// Returns the properties of the `Auth` packet.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bytes::Bytes;
    /// use mqute_codec::protocol::v5::{Auth, AuthProperties, ReasonCode};
    ///
    /// let properties = AuthProperties {
    ///     auth_method: Some("method".to_string()),
    ///     auth_data: Some(Bytes::from("data")),
    ///     reason_string: Some("reason".to_string()),
    ///     user_properties: vec![("key".to_string(), "value".to_string())],
    /// };
    /// let auth = Auth::new(ReasonCode::ContinueAuthentication, Some(properties.clone()));
    /// assert_eq!(auth.properties(), Some(properties));
    /// ```
    pub fn properties(&self) -> Option<AuthProperties> {
        self.header.properties.clone()
    }
}

impl Encode for Auth {
    /// Encodes the `Auth` packet into a byte buffer.
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::Auth, self.payload_len());
        header.encode(buf)?;

        self.header.encode(buf)
    }

    /// Returns the length of the `Auth` packet payload.
    fn payload_len(&self) -> usize {
        self.header.encoded_len()
    }
}

impl Decode for Auth {
    /// Decodes an `Auth` packet from a raw MQTT packet.
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::Auth || !packet.header.flags().is_default() {
            return Err(Error::MalformedPacket);
        }

        let header = AuthHeader::decode(&mut packet.payload)?;
        Ok(Auth { header })
    }
}
