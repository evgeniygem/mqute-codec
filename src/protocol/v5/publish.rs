use super::property::{property_decode, property_encode, property_len, Property, PropertyFrame};
use crate::codec::util::{decode_byte, decode_variable_integer, encode_variable_integer};
use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::util::len_bytes;
use crate::protocol::{common, FixedHeader, Flags, PacketType};
use crate::{Error, QoS};
use bytes::{Buf, Bytes, BytesMut};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PublishProperties {
    pub payload_format_indicator: Option<u8>,
    pub message_expiry_interval: Option<u32>,
    pub topic_alias: Option<u16>,
    pub response_topic: Option<String>,
    pub correlation_data: Option<Bytes>,
    pub user_properties: Vec<(String, String)>,
    pub subscription_id: Vec<u32>,
    pub content_type: Option<String>,
}

impl PropertyFrame for PublishProperties {
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
        property_encode!(&self.user_properties, Property::UserProperty, buf);
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
        let mut message_expiry_interval: Option<u32> = None;
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
                Property::UserProperty => {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublishHeader {
    pub(crate) inner: common::PublishHeader,
    pub(crate) properties: Option<PublishProperties>,
}

impl PublishHeader {
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

    pub(crate) fn encoded_len(&self, qos: QoS) -> usize {
        let properties_len = self
            .properties
            .as_ref()
            .map(|properties| properties.encoded_len())
            .unwrap_or(0);

        self.inner.encoded_len(qos) + len_bytes(properties_len) + properties_len
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut, qos: QoS) -> Result<(), Error> {
        self.inner.encode(buf, qos);

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

    pub(crate) fn decode(payload: &mut Bytes, qos: QoS) -> Result<Self, Error> {
        let inner = common::PublishHeader::decode(payload, qos)?;

        let properties_len = decode_variable_integer(payload)? as usize;
        if payload.len() < properties_len + len_bytes(properties_len) {
            return Err(Error::MalformedPacket);
        }

        // Skip variable byte
        payload.advance(len_bytes(properties_len));

        let mut properties_buf = payload.split_to(properties_len);

        // Deserialize properties
        let properties = PublishProperties::decode(&mut properties_buf)?;
        Ok(PublishHeader { inner, properties })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    header: PublishHeader,
    payload: Bytes,
    flags: Flags,
}

impl Publish {
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

    pub fn flags(&self) -> Flags {
        self.flags
    }

    pub fn packet_id(&self) -> Option<u16> {
        if self.flags.qos != QoS::AtMostOnce {
            Some(self.header.inner.packet_id)
        } else {
            None
        }
    }

    pub fn topic(&self) -> String {
        self.header.inner.topic.clone()
    }

    pub fn properties(&self) -> Option<PublishProperties> {
        self.header.properties.clone()
    }

    pub fn payload(&self) -> Bytes {
        self.payload.clone()
    }
}

impl Decode for Publish {
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
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::with_flags(PacketType::Publish, self.flags, self.payload_len());
        header.encode(buf)?;
        self.header.encode(buf, self.flags.qos)?;

        // Append message
        buf.extend_from_slice(&self.payload);
        Ok(())
    }

    fn payload_len(&self) -> usize {
        self.header.encoded_len(self.flags.qos) + self.payload.len()
    }
}
