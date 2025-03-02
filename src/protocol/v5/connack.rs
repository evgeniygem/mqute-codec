use super::property::{
    property_decode, property_decode_non_zero, property_encode, property_len, Property,
    PropertyFrame,
};
use crate::codec::util::{decode_byte, decode_variable_integer, encode_variable_integer};
use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::util::len_bytes;
use crate::protocol::v5::reason::ReasonCode;
use crate::protocol::{FixedHeader, PacketType};
use crate::{Error, QoS};
use bit_field::BitField;
use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConnAckProperties {
    session_expiry_interval: Option<u32>,
    receive_maximum: Option<u16>,
    maximum_qos: Option<QoS>,
    retain_available: Option<bool>,
    maximum_packet_size: Option<u32>,
    assigned_client_id: Option<String>,
    topic_alias_maximum: Option<u16>,
    reason: Option<String>,
    user_properties: Vec<(String, String)>,
    wildcard_subscription_available: Option<bool>,
    subscription_id_available: Option<bool>,
    shared_subscription_available: Option<bool>,
    server_keep_alive: Option<u16>,
    response_info: Option<String>,
    server_reference: Option<String>,
    auth_method: Option<String>,
    auth_data: Option<Bytes>,
}

impl PropertyFrame for ConnAckProperties {
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

    fn decode(buf: &mut Bytes) -> Result<Option<Self>, Error>
    where
        Self: Sized,
    {
        if buf.is_empty() {
            return Ok(None);
        }

        let mut session_expiry_interval: Option<u32> = None;
        let mut receive_maximum: Option<u16> = None;
        let mut maximum_qos: Option<QoS> = None;
        let mut retain_available: Option<bool> = None;
        let mut maximum_packet_size: Option<u32> = None;
        let mut assigned_client_id: Option<String> = None;
        let mut topic_alias_maximum: Option<u16> = None;
        let mut reason: Option<String> = None;
        let mut user_properties: Vec<(String, String)> = Vec::new();
        let mut wildcard_subscription_available: Option<bool> = None;
        let mut subscription_id_available: Option<bool> = None;
        let mut shared_subscription_available: Option<bool> = None;
        let mut server_keep_alive: Option<u16> = None;
        let mut response_info: Option<String> = None;
        let mut server_reference: Option<String> = None;
        let mut auth_method: Option<String> = None;
        let mut auth_data: Option<Bytes> = None;

        while buf.has_remaining() {
            let property: Property = decode_byte(buf)?.try_into()?;
            match property {
                Property::SessionExpiryInterval => {
                    property_decode!(&mut session_expiry_interval, buf);
                }
                Property::ReceiveMaximum => {
                    property_decode_non_zero!(&mut receive_maximum, buf);
                }
                Property::MaximumQoS => {
                    property_decode!(&mut maximum_qos, buf);
                }
                Property::RetainAvailable => {
                    property_decode!(&mut retain_available, buf);
                }
                Property::MaximumPacketSize => {
                    property_decode_non_zero!(&mut maximum_packet_size, buf);
                }
                Property::AssignedClientIdentifier => {
                    property_decode!(&mut assigned_client_id, buf);
                }
                Property::TopicAliasMaximum => {
                    property_decode!(&mut topic_alias_maximum, buf);
                }
                Property::ReasonString => {
                    property_decode!(&mut reason, buf);
                }
                Property::UserProperty => {
                    property_decode!(&mut user_properties, buf);
                }
                Property::WildcardSubscriptionAvailable => {
                    property_decode!(&mut wildcard_subscription_available, buf);
                }
                Property::SubscriptionIdentifierAvailable => {
                    property_decode!(&mut subscription_id_available, buf);
                }
                Property::SharedSubscriptionAvailable => {
                    property_decode!(&mut shared_subscription_available, buf);
                }
                Property::ServerKeepAlive => {
                    property_decode!(&mut server_keep_alive, buf);
                }
                Property::ResponseInformation => {
                    property_decode!(&mut response_info, buf);
                }
                Property::ServerReference => {
                    property_decode!(&mut server_reference, buf);
                }
                Property::AuthenticationMethod => {
                    property_decode!(&mut auth_method, buf);
                }
                Property::AuthenticationData => {
                    property_decode!(&mut auth_data, buf);
                }
                _ => return Err(Error::PropertyMismatch),
            }
        }

        Ok(Some(ConnAckProperties {
            session_expiry_interval,
            receive_maximum,
            maximum_qos,
            retain_available,
            maximum_packet_size,
            assigned_client_id,
            topic_alias_maximum,
            reason,
            user_properties,
            wildcard_subscription_available,
            subscription_id_available,
            shared_subscription_available,
            server_keep_alive,
            response_info,
            server_reference,
            auth_method,
            auth_data,
        }))
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnAck {
    header: ConnAckHeader,
}

impl ConnAck {
    pub fn new(
        code: ReasonCode,
        session_present: bool,
        properties: Option<ConnAckProperties>,
    ) -> Self {
        ConnAck {
            header: ConnAckHeader::new(code, session_present, properties),
        }
    }

    pub fn code(&self) -> ReasonCode {
        self.header.code
    }

    pub fn session_present(&self) -> bool {
        self.header.session_present
    }

    pub fn properties(&self) -> Option<ConnAckProperties> {
        self.header.properties.clone()
    }
}

impl Encode for ConnAck {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::ConnAck, self.payload_len());
        header.encode(buf)?;
        self.header.encode(buf)
    }

    fn payload_len(&self) -> usize {
        self.header.encoded_len()
    }
}

impl Decode for ConnAck {
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::ConnAck || !packet.header.flags().is_default()
        {
            return Err(Error::MalformedPacket);
        }

        let header = ConnAckHeader::decode(&mut packet.payload)?;
        Ok(ConnAck { header })
    }
}
