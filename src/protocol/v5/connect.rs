use super::property::{property_decode, property_decode_non_zero, property_encode};
use super::property::{property_len, Property, PropertyFrame};
use crate::codec::util::{
    decode_byte, decode_bytes, decode_string, decode_variable_integer, encode_bytes, encode_string,
    encode_variable_integer,
};
use crate::protocol::common::frame::{ConnectFrame, WillFrame};
use crate::protocol::common::{connect, ConnectHeader};
use crate::protocol::util::len_bytes;
use crate::protocol::{Auth, Protocol};
use crate::{Error, QoS};
use bit_field::BitField;
use bytes::{Buf, Bytes, BytesMut};
use std::ops::RangeInclusive;

const WILL_FLAG: usize = 2;
const WILL_QOS: RangeInclusive<usize> = 3..=4;
const WILL_RETAIN: usize = 5;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConnectProperties {
    pub session_expiry_interval: Option<u32>,
    pub receive_maximum: Option<u16>,
    pub maximum_packet_size: Option<u32>,
    pub topic_alias_maximum: Option<u16>,
    pub request_response_info: Option<bool>,
    pub request_problem_info: Option<bool>,
    pub user_properties: Vec<(String, String)>,
    pub auth_method: Option<String>,
    pub auth_data: Option<Bytes>,
}

impl PropertyFrame for ConnectProperties {
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
        property_encode!(&self.user_properties, Property::UserProperty, buf);
        property_encode!(&self.auth_method, Property::AuthenticationMethod, buf);
        property_encode!(&self.auth_data, Property::AuthenticationData, buf);
    }

    fn decode(buf: &mut Bytes) -> Result<Option<Self>, Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        let mut session_expiry_interval: Option<u32> = None;
        let mut receive_maximum: Option<u16> = None;
        let mut maximum_packet_size: Option<u32> = None;
        let mut topic_alias_maximum: Option<u16> = None;
        let mut request_response_info: Option<bool> = None;
        let mut request_problem_info: Option<bool> = None;
        let mut user_properties: Vec<(String, String)> = Vec::new();
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
                Property::MaximumPacketSize => {
                    property_decode_non_zero!(&mut maximum_packet_size, buf);
                }
                Property::TopicAliasMaximum => {
                    property_decode!(&mut topic_alias_maximum, buf);
                }
                Property::RequestResponseInformation => {
                    property_decode!(&mut request_response_info, buf);
                }
                Property::RequestProblemInformation => {
                    property_decode!(&mut request_problem_info, buf);
                }
                Property::UserProperty => {
                    property_decode!(&mut user_properties, buf);
                }
                Property::AuthenticationMethod => {
                    property_decode!(&mut auth_method, buf);
                }
                Property::AuthenticationData => {
                    property_decode!(&mut auth_data, buf);
                }
                _ => return Err(Error::PropertyMismatch),
            };
        }

        if auth_data.is_some() && auth_method.is_none() {
            return Err(Error::ProtocolError);
        }

        Ok(Some(ConnectProperties {
            session_expiry_interval,
            receive_maximum,
            maximum_packet_size,
            topic_alias_maximum,
            request_response_info,
            request_problem_info,
            user_properties,
            auth_method,
            auth_data,
        }))
    }
}

impl ConnectFrame for ConnectHeader<ConnectProperties> {
    fn encoded_len(&self) -> usize {
        let properties_len = self
            .properties
            .as_ref()
            .map(|properties| properties.encoded_len())
            .unwrap_or(0);
        properties_len + len_bytes(properties_len) + self.primary_encoded_len()
    }

    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        // Encode protocol name, level, flags, keep alive
        self.primary_encode(buf);

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

    fn decode(buf: &mut Bytes) -> Result<Self, Error>
    where
        Self: Sized,
    {
        // Decode protocol name, level, flags, keep alive without properties
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

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WillProperties {
    pub delay_interval: Option<u32>,
    pub payload_format_indicator: Option<u8>,
    pub message_expiry_interval: Option<u32>,
    pub content_type: Option<String>,
    pub response_topic: Option<String>,
    pub correlation_data: Option<Bytes>,
    pub user_properties: Vec<(String, String)>,
}

impl PropertyFrame for WillProperties {
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
        property_encode!(&self.user_properties, Property::UserProperty, buf);
    }

    fn decode(buf: &mut Bytes) -> Result<Option<Self>, Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        let mut delay_interval: Option<u32> = None;
        let mut payload_format_indicator: Option<u8> = None;
        let mut message_expiry_interval: Option<u32> = None;
        let mut content_type: Option<String> = None;
        let mut response_topic: Option<String> = None;
        let mut correlation_data: Option<Bytes> = None;
        let mut user_properties: Vec<(String, String)> = Vec::new();

        while buf.has_remaining() {
            let property: Property = decode_byte(buf)?.try_into()?;
            match property {
                Property::WillDelayInterval => {
                    property_decode!(&mut delay_interval, buf);
                }
                Property::PayloadFormatIndicator => {
                    property_decode!(&mut payload_format_indicator, buf);
                    if let Some(value) = payload_format_indicator {
                        if value != 0 && value != 1 {
                            return Err(Error::ProtocolError);
                        }
                    }
                }
                Property::MessageExpiryInterval => {
                    property_decode!(&mut message_expiry_interval, buf);
                }
                Property::ContentType => {
                    property_decode!(&mut content_type, buf);
                }
                Property::ResponseTopic => {
                    property_decode!(&mut response_topic, buf);
                }
                Property::CorrelationData => {
                    property_decode!(&mut correlation_data, buf);
                }
                Property::UserProperty => {
                    property_decode!(&mut user_properties, buf);
                }
                _ => return Err(Error::PropertyMismatch),
            }
        }

        Ok(Some(WillProperties {
            delay_interval,
            payload_format_indicator,
            message_expiry_interval,
            content_type,
            response_topic,
            correlation_data,
            user_properties,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Will {
    pub properties: Option<WillProperties>,
    pub topic: String,
    pub payload: Bytes,
    pub qos: QoS,
    pub retain: bool,
}

impl WillFrame for Will {
    fn encoded_len(&self) -> usize {
        let properties_len = self
            .properties
            .as_ref()
            .map(|properties| properties.encoded_len())
            .unwrap_or(0);

        2 + self.topic.len() + 2 + self.payload.len() + len_bytes(properties_len) + properties_len
    }

    fn update_flags(&self, flags: &mut u8) {
        // Update the 'Will' flag
        flags.set_bit(WILL_FLAG, true);

        // Update 'Qos' flags
        flags.set_bits(WILL_QOS, self.qos as u8);

        // Update the 'Will Retain' flag
        flags.set_bit(WILL_RETAIN, self.retain);
    }

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

connect!(Connect<ConnectProperties, Will>, Protocol::V5);

impl Connect {
    pub fn with_properties<S: Into<String>>(
        client_id: S,
        auth: Option<Auth>,
        will: Option<Will>,
        properties: ConnectProperties,
        keep_alive: u16,
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

    pub fn properties(&self) -> Option<ConnectProperties> {
        self.header.properties.clone()
    }
}
