use crate::codec::util::decode_word;
use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::{FixedHeader, Flags, PacketType};
use crate::protocol::{TopicQosFilter, TopicQosFilters};
use crate::{Error, QoS};
use bytes::{BufMut, BytesMut};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscribe {
    packet_id: u16,
    filters: TopicQosFilters,
}

impl Subscribe {
    pub fn new<T: IntoIterator<Item = TopicQosFilter>>(packet_id: u16, filters: T) -> Self {
        if packet_id == 0 {
            panic!("Packet id is zero");
        }

        let filters = filters.into_iter().collect();
        Subscribe { packet_id, filters }
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

        let packet_id = decode_word(&mut packet.payload)?;
        let filters = TopicQosFilters::decode(&mut packet.payload)?;

        Ok(Subscribe::new(packet_id, filters))
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
        buf.put_u16(self.packet_id);
        self.filters.encode(buf);

        Ok(())
    }

    fn payload_len(&self) -> usize {
        // Packet ID and filter list
        2 + self.filters.encoded_len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use crate::QoS;
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    #[test]
    fn subscribe_decode() {
        let mut codec = PacketCodec::new(None, None);

        let data = &[
            (PacketType::Subscribe as u8) << 4 | 0b0010, // Packet type
            0x0c,                                        // Remaining len
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
                    TopicQosFilter::new("/a", QoS::AtMostOnce),
                    TopicQosFilter::new("/b", QoS::ExactlyOnce)
                ]
            )
        );
    }

    #[test]
    fn subscribe_encode() {
        let packet = Subscribe::new(
            0x1234,
            vec![
                TopicQosFilter::new("/a", QoS::AtMostOnce),
                TopicQosFilter::new("/b", QoS::ExactlyOnce),
            ],
        );

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(
            stream,
            vec![
                (PacketType::Subscribe as u8) << 4 | 0b0010, // Packet type
                0x0c,                                        // Remaining len
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
