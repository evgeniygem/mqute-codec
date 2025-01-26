use crate::codec::util::decode_word;
use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::common::util;
use crate::protocol::{FixedHeader, Flags, PacketType};
use crate::{Error, QoS};
use bytes::BufMut;

// Create 'PubRel' packet
util::id_packet!(PubRel);

impl Encode for PubRel {
    fn encode(&self, buf: &mut bytes::BytesMut) -> Result<(), Error> {
        let header = FixedHeader::with_flags(
            PacketType::PubRel,
            Flags::new(QoS::AtLeastOnce),
            self.payload_len(),
        );
        header.encode(buf)?;

        buf.put_u16(self.packet_id);
        Ok(())
    }

    fn payload_len(&self) -> usize {
        2
    }

    fn encoded_len(&self) -> usize {
        2 + 2 // Fixed header size + variable header size
    }
}

impl Decode for PubRel {
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::PubRel
            || packet.header.flags() != Flags::new(QoS::AtLeastOnce)
        {
            return Err(Error::MalformedPacket);
        }
        let packet_id = decode_word(&mut packet.payload)?;
        Ok(PubRel::new(packet_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use crate::codec::{Decode, Encode};
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    #[test]
    fn pubrel_decode() {
        let mut codec = PacketCodec::new(None, None);

        let data = &[
            (PacketType::PubRel as u8) << 4 | 0b0010, // Packet type
            0x02,                                     // Remaining len
            0x12,                                     // Packet ID
            0x34,
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = PubRel::decode(raw_packet).unwrap();

        assert_eq!(packet, PubRel::new(0x1234));
    }

    #[test]
    fn pubrel_encode() {
        let packet = PubRel::new(0x1234);

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(
            stream,
            vec![(PacketType::PubRel as u8) << 4 | 0b0010, 0x02, 0x12, 0x34]
        );
    }
}
