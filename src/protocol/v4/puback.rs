use crate::codec::util::decode_word;
use crate::codec::{Decode, Encode, RawPacket};
use crate::error::Error;
use crate::header::FixedHeader;
use crate::packet::PacketType;
use bytes::{BufMut, BytesMut};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PubAck {
    packet_id: u16,
}

impl PubAck {
    pub fn new(packet_id: u16) -> Self {
        PubAck { packet_id }
    }
}

impl Decode for PubAck {
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::PubAck || packet.header.flags() != 0 {
            return Err(Error::MalformedPacket);
        }

        let packet_id = decode_word(&mut packet.payload)?;

        // Ignores other fields if mqtt has version 5
        Ok(PubAck::new(packet_id))
    }
}

impl Encode for PubAck {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::PubAck, 0, self.payload_len());
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
    fn puback_decode() {
        let mut codec = PacketCodec::new(None, None);

        let data = &[
            (PacketType::PubAck as u8) << 4, // Packet type
            0x02,                            // Remaining len
            0x12,                            // Packet ID
            0x34,
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = PubAck::decode(raw_packet).unwrap();

        assert_eq!(packet, PubAck::new(0x1234));
    }

    #[test]
    fn puback_encode() {
        let packet = PubAck::new(0x1234);

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(
            stream,
            vec![(PacketType::PubAck as u8) << 4, 0x02, 0x12, 0x34]
        );
    }
}
