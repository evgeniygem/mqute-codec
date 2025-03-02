use crate::codec::util::{
    decode_byte, decode_string, decode_variable_integer, encode_string, encode_variable_integer,
};
use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::util::len_bytes;
use crate::protocol::v5::property::{
    property_decode, property_encode, property_len, Property, PropertyFrame,
};
use crate::protocol::v5::util::id_header;
use crate::protocol::{FixedHeader, Flags, PacketType, QoS};
use crate::Error;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::borrow::Borrow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeProperties {
    pub subscription_id: Option<u32>,
    pub user_properties: Vec<(String, String)>,
}

impl PropertyFrame for SubscribeProperties {
    fn encoded_len(&self) -> usize {
        let mut len = 0usize;

        if let Some(value) = self.subscription_id {
            len += 1 + len_bytes(value as usize);
        }
        len += property_len!(&self.user_properties);

        len
    }

    fn encode(&self, buf: &mut BytesMut) {
        if let Some(value) = self.subscription_id {
            buf.put_u8(Property::SubscriptionIdentifier.into());
            encode_variable_integer(buf, value).expect("");
        }

        property_encode!(&self.user_properties, Property::UserProperty, buf);
    }

    fn decode(buf: &mut bytes::Bytes) -> Result<Option<Self>, Error>
    where
        Self: Sized,
    {
        if buf.is_empty() {
            return Ok(None);
        }

        let mut subscription_id: Option<u32> = None;
        let mut user_properties: Vec<(String, String)> = Vec::new();

        while buf.has_remaining() {
            let property: Property = decode_byte(buf)?.try_into()?;
            match property {
                Property::SubscriptionIdentifier => {
                    if subscription_id.is_some() {
                        return Err(Error::ProtocolError);
                    }
                    subscription_id = Some(decode_variable_integer(buf)? as u32);
                }
                Property::UserProperty => {
                    property_decode!(&mut user_properties, buf);
                }
                _ => return Err(Error::PropertyMismatch),
            }
        }

        Ok(Some(SubscribeProperties {
            subscription_id,
            user_properties,
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub enum RetainHandling {
    Send = 0,
    SendForNewSub = 1,
    DoNotSend = 2,
}

impl TryFrom<u8> for RetainHandling {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(RetainHandling::Send),
            1 => Ok(RetainHandling::SendForNewSub),
            2 => Ok(RetainHandling::DoNotSend),
            n => Err(Error::InvalidRetainHandling(n)),
        }
    }
}

impl Into<u8> for RetainHandling {
    fn into(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicOptionFilter {
    pub topic: String,
    pub qos: QoS,
    pub no_local: bool,
    pub retain_as_published: bool,
    pub retain_handling: RetainHandling,
}

impl TopicOptionFilter {
    pub fn new<S: Into<String>>(
        topic: S,
        qos: QoS,
        no_local: bool,
        retain_as_published: bool,
        retain_handling: RetainHandling,
    ) -> Self {
        TopicOptionFilter {
            topic: topic.into(),
            qos,
            no_local,
            retain_as_published,
            retain_handling,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicOptionFilters(Vec<TopicOptionFilter>);

impl TopicOptionFilters {
    pub fn new<T: IntoIterator<Item = TopicOptionFilter>>(filters: T) -> Self {
        let values: Vec<TopicOptionFilter> = filters.into_iter().collect();

        if values.is_empty() {
            panic!("At least one topic filter is required");
        }

        TopicOptionFilters(values)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn decode(payload: &mut Bytes) -> Result<Self, Error> {
        let mut filters = Vec::with_capacity(1);

        while payload.has_remaining() {
            let topic = decode_string(payload)?;
            let flags = decode_byte(payload)?;

            // The upper 2 bits of the requested option byte must be zero
            if flags & 0b1100_0000 > 0 {
                return Err(Error::MalformedPacket);
            }

            let qos = (flags & 0x03).try_into()?;
            let no_local = flags & 0x04 != 0;
            let retain_as_published = flags & 0x08 != 0;
            let retain_handling = ((flags >> 4) & 0x03).try_into()?;

            filters.push(TopicOptionFilter::new(
                topic,
                qos,
                no_local,
                retain_as_published,
                retain_handling,
            ));
        }

        if filters.is_empty() {
            return Err(Error::NoTopic);
        }

        Ok(TopicOptionFilters(filters))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        self.0.iter().for_each(|f| {
            let qos: u8 = f.qos.into();
            let retain_handling: u8 = f.retain_handling.into();

            let options: u8 = retain_handling << 4
                | (f.retain_as_published as u8) << 3
                | (f.no_local as u8) << 2
                | qos;

            encode_string(buf, &f.topic);
            buf.put_u8(options);
        });
    }

    pub(crate) fn encoded_len(&self) -> usize {
        self.0.iter().fold(0, |acc, f| acc + 2 + f.topic.len() + 1)
    }
}

impl AsRef<Vec<TopicOptionFilter>> for TopicOptionFilters {
    #[inline]
    fn as_ref(&self) -> &Vec<TopicOptionFilter> {
        self.0.as_ref()
    }
}

impl Borrow<Vec<TopicOptionFilter>> for TopicOptionFilters {
    fn borrow(&self) -> &Vec<TopicOptionFilter> {
        self.0.as_ref()
    }
}

impl IntoIterator for TopicOptionFilters {
    type Item = TopicOptionFilter;
    type IntoIter = std::vec::IntoIter<TopicOptionFilter>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl FromIterator<TopicOptionFilter> for TopicOptionFilters {
    fn from_iter<T: IntoIterator<Item = TopicOptionFilter>>(iter: T) -> Self {
        TopicOptionFilters(Vec::from_iter(iter))
    }
}

impl Into<Vec<TopicOptionFilter>> for TopicOptionFilters {
    #[inline]
    fn into(self) -> Vec<TopicOptionFilter> {
        self.0
    }
}

impl From<Vec<TopicOptionFilter>> for TopicOptionFilters {
    #[inline]
    fn from(value: Vec<TopicOptionFilter>) -> Self {
        TopicOptionFilters(value)
    }
}

id_header!(SubscribeHeader, SubscribeProperties);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscribe {
    header: SubscribeHeader,
    filters: TopicOptionFilters,
}

impl Subscribe {
    pub fn new<T: IntoIterator<Item = TopicOptionFilter>>(
        packet_id: u16,
        properties: Option<SubscribeProperties>,
        filters: T,
    ) -> Self {
        let header = SubscribeHeader::new(packet_id, properties);
        let filters = TopicOptionFilters::new(filters);

        Subscribe { header, filters }
    }

    pub fn packet_id(&self) -> u16 {
        self.header.packet_id
    }

    pub fn properties(&self) -> Option<SubscribeProperties> {
        self.header.properties.clone()
    }

    pub fn filters(&self) -> TopicOptionFilters {
        self.filters.clone()
    }
}

impl Encode for Subscribe {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::with_flags(
            PacketType::Subscribe,
            Flags::new(QoS::AtLeastOnce),
            self.payload_len(),
        );
        header.encode(buf)?;

        self.header.encode(buf)?;
        self.filters.encode(buf);

        Ok(())
    }

    fn payload_len(&self) -> usize {
        self.header.encoded_len() + self.filters.encoded_len()
    }
}

impl Decode for Subscribe {
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        // Validate header flags
        if packet.header.packet_type() != PacketType::Subscribe
            || packet.header.flags() != Flags::new(QoS::AtLeastOnce)
        {
            return Err(Error::MalformedPacket);
        }

        let header = SubscribeHeader::decode(&mut packet.payload)?;
        let filters = TopicOptionFilters::decode(&mut packet.payload)?;

        Ok(Subscribe::new(header.packet_id, header.properties, filters))
    }
}
