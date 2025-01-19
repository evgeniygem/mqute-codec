use crate::codec::util::{decode_byte, decode_string, decode_word, encode_string};
use crate::codec::{Decode, Encode, RawPacket};
use crate::error::Error;
use crate::header::FixedHeader;
use crate::packet::PacketType;
use crate::qos::QoS;
use bytes::{Buf, BufMut, BytesMut};

const SUBSCRIBE_FLAGS: u8 = 0b0010;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicFilter {
    filter: String,
    qos: QoS,
}

impl TopicFilter {
    pub fn new<T: Into<String>>(filter: T, qos: QoS) -> Self {
        Self {
            filter: filter.into(),
            qos,
        }
    }

    pub fn size(&self) -> usize {
        2 + self.filter.len() + 1
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let flags = self.qos as u8;
        encode_string(buf, &self.filter);
        buf.put_u8(flags);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscribe {
    packet_id: u16,
    filters: Vec<TopicFilter>,
}

impl Subscribe {
    pub fn new(packet_id: u16, filters: Vec<TopicFilter>) -> Self {
        if filters.is_empty() {
            panic!("At least one topic is required");
        }

        if packet_id == 0 {
            panic!("Packet id is zero");
        }

        Subscribe { packet_id, filters }
    }

    pub fn from_topics<T>(packet_id: u16, topics: T) -> Self
    where
        T: IntoIterator<Item = TopicFilter>,
    {
        let filters: Vec<TopicFilter> = topics.into_iter().collect();
        if filters.is_empty() {
            panic!("At least one topic is required");
        }

        Subscribe { packet_id, filters }
    }
}

impl Decode for Subscribe {
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        // Validate header flags
        if packet.header.packet_type() != PacketType::Subscribe
            || packet.header.flags() != SUBSCRIBE_FLAGS
        {
            return Err(Error::MalformedPacket);
        }

        let mut filters: Vec<TopicFilter> = Vec::new();

        let packet_id = decode_word(&mut packet.payload)?;
        while packet.payload.has_remaining() {
            let filter = decode_string(&mut packet.payload)?;
            let flags = decode_byte(&mut packet.payload)?;

            // The upper 6 bits of the Requested QoS byte must be zero
            if flags & 0b1111_1100 > 0 {
                return Err(Error::MalformedPacket);
            }

            filters.push(TopicFilter::new(filter, flags.try_into()?));
        }

        if filters.is_empty() {
            return Err(Error::NoSubscription);
        }

        Ok(Subscribe::new(packet_id, filters))
    }
}

impl Encode for Subscribe {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::Subscribe, SUBSCRIBE_FLAGS, self.payload_len());
        header.encode(buf)?;
        buf.put_u16(self.packet_id);

        self.filters.iter().for_each(|f| f.encode(buf));

        Ok(())
    }

    fn payload_len(&self) -> usize {
        2 + self
            .filters
            .iter()
            .fold(0, |acc, filter| acc + filter.size())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    #[test]
    fn subscribe_decode() {
        let mut codec = PacketCodec::new(None, None);

        let data = &[
            (PacketType::Subscribe as u8) << 4 | SUBSCRIBE_FLAGS, // Packet type
            0x0c,                                                 // Remaining len
            0x12,
            0x34,
            0x00,
            0x02,
            b'/',
            b'a',
            0x00,
            0x00,
            0x02,
            b'/',
            b'b',
            0x02,
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = Subscribe::decode(raw_packet).unwrap();

        assert_eq!(
            packet,
            Subscribe::new(
                0x1234,
                vec![
                    TopicFilter::new("/a", QoS::AtMostOnce),
                    TopicFilter::new("/b", QoS::ExactlyOnce)
                ]
            )
        );
    }

    #[test]
    fn subscribe_encode() {
        let packet = Subscribe::new(
            0x1234,
            vec![
                TopicFilter::new("/a", QoS::AtMostOnce),
                TopicFilter::new("/b", QoS::ExactlyOnce),
            ],
        );

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(
            stream,
            vec![
                (PacketType::Subscribe as u8) << 4 | SUBSCRIBE_FLAGS, // Packet type
                0x0c,                                                 // Remaining len
                0x12,
                0x34,
                0x00,
                0x02,
                b'/',
                b'a',
                0x00,
                0x00,
                0x02,
                b'/',
                b'b',
                0x02,
            ]
        );
    }
}
