use crate::codec::util::decode_word;
use crate::codec::{Decode, Encode, RawPacket};
use crate::error::Error;
use crate::header::FixedHeader;
use crate::packet::PacketType;
use bytes::{BufMut, BytesMut};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PubRec {
    packet_id: u16,
}

impl PubRec {
    pub fn new(packet_id: u16) -> Self {
        PubRec { packet_id }
    }
}

impl Decode for PubRec {
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::PubRec || packet.header.flags() != 0 {
            return Err(Error::MalformedPacket);
        }
        let packet_id = decode_word(&mut packet.payload)?;

        // Ignores other fields if mqtt has version 5
        Ok(PubRec::new(packet_id))
    }
}

impl Encode for PubRec {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::PubRec, 0, self.payload_len());
        header.encode(buf)?;

        buf.put_u16(self.packet_id);
        Ok(())
    }

    fn payload_len(&self) -> usize {
        2
    }

    fn packet_len(&self) -> usize {
        2 + 2 // Fixed header size + variable header size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    #[test]
    fn pubrec_decode() {
        let mut codec = PacketCodec::new(None, None);

        let data = &[
            (PacketType::PubRec as u8) << 4, // Packet type
            0x02,                            // Remaining len
            0x12,                            // Packet ID
            0x34,
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = PubRec::decode(raw_packet).unwrap();

        assert_eq!(packet, PubRec::new(0x1234));
    }

    #[test]
    fn pubrec_encode() {
        let packet = PubRec::new(0x1234);

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(
            stream,
            vec![(PacketType::PubRec as u8) << 4, 0x02, 0x12, 0x34]
        );
    }
}
