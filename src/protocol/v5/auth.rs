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

fn validate_auth_reason_code(code: ReasonCode) -> bool {
    matches!(code.into(), 0 | 24 | 25)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthProperties {
    pub auth_method: Option<String>,
    pub auth_data: Option<Bytes>,
    pub reason_string: Option<String>,
    pub user_properties: Vec<(String, String)>,
}

impl PropertyFrame for AuthProperties {
    fn encoded_len(&self) -> usize {
        let mut len = 0usize;

        len += property_len!(&self.auth_method);
        len += property_len!(&self.auth_data);
        len += property_len!(&self.reason_string);
        len += property_len!(&self.user_properties);

        len
    }

    fn encode(&self, buf: &mut BytesMut) {
        property_encode!(&self.auth_method, Property::AuthenticationMethod, buf);
        property_encode!(&self.auth_data, Property::AuthenticationData, buf);
        property_encode!(&self.reason_string, Property::ReasonString, buf);
        property_encode!(&self.user_properties, Property::UserProperty, buf);
    }

    fn decode(buf: &mut Bytes) -> Result<Option<Self>, Error>
    where
        Self: Sized,
    {
        if buf.is_empty() {
            return Ok(None);
        }

        let mut auth_method: Option<String> = None;
        let mut auth_data: Option<Bytes> = None;
        let mut reason_string: Option<String> = None;
        let mut user_properties: Vec<(String, String)> = Vec::new();

        while buf.has_remaining() {
            let property: Property = decode_byte(buf)?.try_into()?;
            match property {
                Property::AuthenticationMethod => {
                    property_decode!(&mut auth_method, buf);
                }
                Property::AuthenticationData => {
                    property_decode!(&mut auth_data, buf);
                }
                Property::ReasonString => {
                    property_decode!(&mut reason_string, buf);
                }
                Property::UserProperty => {
                    property_decode!(&mut user_properties, buf);
                }
                _ => return Err(Error::PropertyMismatch),
            }
        }

        Ok(Some(AuthProperties {
            auth_method,
            auth_data,
            reason_string,
            user_properties,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthHeader {
    code: ReasonCode,
    properties: Option<AuthProperties>,
}

impl AuthHeader {
    pub(crate) fn new(code: ReasonCode, properties: Option<AuthProperties>) -> Self {
        if !validate_auth_reason_code(code) {
            panic!("Invalid reason code");
        }
        AuthHeader { code, properties }
    }

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

    pub(crate) fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        // The reason code and property can be omitted if the code is 0x00 and there are no properties
        if self.code == ReasonCode::Success && self.properties.is_none() {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    header: AuthHeader,
}

impl Auth {
    pub fn new(code: ReasonCode, properties: Option<AuthProperties>) -> Self {
        Auth {
            header: AuthHeader::new(code, properties),
        }
    }

    pub fn code(&self) -> ReasonCode {
        self.header.code
    }

    pub fn properties(&self) -> Option<AuthProperties> {
        self.header.properties.clone()
    }
}

impl Encode for Auth {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::Auth, self.payload_len());
        header.encode(buf)?;

        self.header.encode(buf)
    }

    fn payload_len(&self) -> usize {
        self.header.encoded_len()
    }
}

impl Decode for Auth {
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::Auth || !packet.header.flags().is_default() {
            return Err(Error::MalformedPacket);
        }

        let header = AuthHeader::decode(&mut packet.payload)?;
        Ok(Auth { header })
    }
}
