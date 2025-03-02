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

fn validate_disconnect_reason_code(code: ReasonCode) -> bool {
    matches!(code.into(), 0 | 4 | 128..=131 | 135 | 137 | 139 | 141..=144 | 147..=162)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisconnectProperties {
    pub session_expiry_interval: Option<u32>,
    pub reason_string: Option<String>,
    pub user_properties: Vec<(String, String)>,
    pub server_reference: Option<String>,
}

impl PropertyFrame for DisconnectProperties {
    fn encoded_len(&self) -> usize {
        let mut len = 0usize;

        len += property_len!(&self.session_expiry_interval);
        len += property_len!(&self.reason_string);
        len += property_len!(&self.user_properties);
        len += property_len!(&self.server_reference);

        len
    }

    fn encode(&self, buf: &mut BytesMut) {
        property_encode!(
            &self.session_expiry_interval,
            Property::SessionExpiryInterval,
            buf
        );

        property_encode!(&self.reason_string, Property::ReasonString, buf);
        property_encode!(&self.user_properties, Property::UserProperty, buf);
        property_encode!(&self.server_reference, Property::ServerReference, buf);
    }

    fn decode(buf: &mut Bytes) -> Result<Option<Self>, Error>
    where
        Self: Sized,
    {
        if buf.is_empty() {
            return Ok(None);
        }
        let mut session_expiry_interval: Option<u32> = None;
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
                Property::UserProperty => {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disconnect {
    header: DisconnectHeader,
}

impl Disconnect {
    pub fn new(code: ReasonCode, properties: Option<DisconnectProperties>) -> Self {
        Disconnect {
            header: DisconnectHeader::new(code, properties),
        }
    }

    pub fn code(&self) -> ReasonCode {
        self.header.code
    }

    pub fn properties(&self) -> Option<DisconnectProperties> {
        self.header.properties.clone()
    }
}

impl Encode for Disconnect {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::Disconnect, self.payload_len());
        header.encode(buf)?;

        self.header.encode(buf)
    }

    fn payload_len(&self) -> usize {
        self.header.encoded_len()
    }
}

impl Decode for Disconnect {
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
