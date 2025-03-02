use crate::codec::util::decode_byte;
use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::v5::property::{
    property_decode, property_encode, property_len, Property, PropertyFrame,
};
use crate::protocol::v5::util::id_header;
use crate::protocol::{FixedHeader, Flags, PacketType, TopicFilters};
use crate::{Error, QoS};
use bytes::{Buf, Bytes, BytesMut};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsubscribeProperties {
    user_properties: Vec<(String, String)>,
}

impl PropertyFrame for UnsubscribeProperties {
    fn encoded_len(&self) -> usize {
        let mut len = 0usize;

        len += property_len!(&self.user_properties);

        len
    }

    fn encode(&self, buf: &mut BytesMut) {
        property_encode!(&self.user_properties, Property::UserProperty, buf);
    }

    fn decode(buf: &mut Bytes) -> Result<Option<Self>, Error>
    where
        Self: Sized,
    {
        if buf.is_empty() {
            return Ok(None);
        }

        let mut user_properties: Vec<(String, String)> = Vec::new();

        while buf.has_remaining() {
            let property: Property = decode_byte(buf)?.try_into()?;
            match property {
                Property::UserProperty => {
                    property_decode!(&mut user_properties, buf);
                }
                _ => return Err(Error::PropertyMismatch),
            }
        }

        Ok(Some(UnsubscribeProperties { user_properties }))
    }
}

id_header!(UnsubscribeHeader, UnsubscribeProperties);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsubscribe {
    header: UnsubscribeHeader,
    filters: TopicFilters,
}

impl Unsubscribe {
    pub fn new<T: IntoIterator<Item = String>>(
        packet_id: u16,
        properties: Option<UnsubscribeProperties>,
        filters: T,
    ) -> Self {
        let filters: Vec<String> = filters.into_iter().collect();

        Unsubscribe {
            header: UnsubscribeHeader::new(packet_id, properties),
            filters: filters.into(),
        }
    }

    pub fn packet_id(&self) -> u16 {
        self.header.packet_id
    }

    pub fn properties(&self) -> Option<UnsubscribeProperties> {
        self.header.properties.clone()
    }

    pub fn filters(&self) -> TopicFilters {
        self.filters.clone()
    }
}

impl Encode for Unsubscribe {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::with_flags(
            PacketType::Unsubscribe,
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

impl Decode for Unsubscribe {
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        // Validate header flags
        if packet.header.packet_type() != PacketType::Unsubscribe
            || packet.header.flags() != Flags::new(QoS::AtLeastOnce)
        {
            return Err(Error::MalformedPacket);
        }

        let header = UnsubscribeHeader::decode(&mut packet.payload)?;
        let filters = TopicFilters::decode(&mut packet.payload)?;

        Ok(Unsubscribe::new(
            header.packet_id,
            header.properties,
            filters,
        ))
    }
}
