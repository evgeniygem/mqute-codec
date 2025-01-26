use crate::codec::util::decode_word;
use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::{FixedHeader, PacketType};
use crate::protocol::{Flags, TopicFilters};
use crate::{Error, QoS};
use bytes::{BufMut, BytesMut};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsubscribe {
    packet_id: u16,
    filters: TopicFilters,
}

impl Unsubscribe {
    pub fn new<T: IntoIterator<Item = String>>(packet_id: u16, filters: T) -> Self {
        if packet_id == 0 {
            panic!("Packet id is zero");
        }

        Unsubscribe {
            packet_id,
            filters: TopicFilters::new(filters),
        }
    }
}

impl Decode for Unsubscribe {
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::Unsubscribe
            || packet.header.flags() != Flags::new(QoS::AtLeastOnce)
        {
            return Err(Error::MalformedPacket);
        }

        let packet_id = decode_word(&mut packet.payload)?;
        let filters = TopicFilters::decode(&mut packet.payload)?;

        Ok(Unsubscribe::new(packet_id, filters))
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

        // Encode the packet id
        buf.put_u16(self.packet_id);
        self.filters.encode(buf);
        Ok(())
    }

    fn payload_len(&self) -> usize {
        2 + self.filters.encoded_len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    fn packet_data() -> &'static [u8] {
        &[
            (PacketType::Unsubscribe as u8) << 4 | 0b0010, // Packet type
            0x16,                                          // Remaining len
            0x12,                                          // Packet ID
            0x34,                                          //
            0x00,                                          // Topic #1 len
            0x0c,                                          //
            b'h',                                          // Topic message
            b'e',
            b'l',
            b'l',
            b'o',
            b' ',
            b'w',
            b'o',
            b'r',
            b'l',
            b'd',
            b'!',
            0x00, // Topic #2 len
            0x04,
            b't', // Topic message
            b'e',
            b's',
            b't',
        ]
    }

    #[test]
    fn unsubscribe_decode() {
        let mut codec = PacketCodec::new(None, None);

        let mut stream = BytesMut::new();

        stream.extend_from_slice(packet_data());

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = Unsubscribe::decode(raw_packet).unwrap();

        assert_eq!(
            packet,
            Unsubscribe::new(0x1234, vec!["hello world!".into(), "test".into()])
        );
    }

    #[test]
    fn unsubscribe_encode() {
        let packet = Unsubscribe::new(0x1234, vec!["hello world!".into(), "test".into()]);

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(stream, Vec::from(packet_data()));
    }

    #[test]
    #[should_panic]
    fn unsubscribe_construct() {
        Unsubscribe::new(0, vec![]);
    }
}
