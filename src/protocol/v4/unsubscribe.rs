use crate::codec::util::{decode_string, decode_word, encode_string};
use crate::codec::{Decode, Encode, RawPacket};
use crate::error::Error;
use crate::header::FixedHeader;
use crate::packet::PacketType;
use bytes::{Buf, BufMut, BytesMut};

const UNSUBSCRIBE_FLAGS: u8 = 0b0010;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsubscribe {
    packet_id: u16,
    filters: Vec<String>,
}

impl Unsubscribe {
    pub fn new(packet_id: u16, filters: Vec<String>) -> Self {
        if filters.is_empty() {
            panic!("At least one topic is required");
        }

        if packet_id == 0 {
            panic!("Packet id is zero");
        }

        Unsubscribe { packet_id, filters }
    }
}

impl Decode for Unsubscribe {
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::Unsubscribe
            || packet.header.flags() != UNSUBSCRIBE_FLAGS
        {
            return Err(Error::MalformedPacket);
        }

        let packet_id = decode_word(&mut packet.payload)?;

        let mut filters = Vec::with_capacity(1);
        while packet.payload.has_remaining() {
            filters.push(decode_string(&mut packet.payload)?);
        }

        if filters.is_empty() {
            return Err(Error::NoSubscription);
        }

        Ok(Unsubscribe::new(packet_id, filters))
    }
}

impl Encode for Unsubscribe {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(
            PacketType::Unsubscribe,
            UNSUBSCRIBE_FLAGS,
            self.payload_len(),
        );
        header.encode(buf)?;

        // Encode the packet id
        buf.put_u16(self.packet_id);

        self.filters
            .iter()
            .for_each(|filter| encode_string(buf, filter));
        Ok(())
    }

    fn payload_len(&self) -> usize {
        2 + self.filters.iter().fold(0, |acc, l| acc + 2 + l.len())
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
            (PacketType::Unsubscribe as u8) << 4 | UNSUBSCRIBE_FLAGS, // Packet type
            0x16,                                                     // Remaining len
            0x12,                                                     // Packet ID
            0x34,                                                     //
            0x00,                                                     // Topic #1 len
            0x0c,                                                     //
            b'h',                                                     // Topic message
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
