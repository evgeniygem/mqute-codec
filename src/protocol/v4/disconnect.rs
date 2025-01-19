use crate::codec::{Decode, Encode, RawPacket};
use crate::error::Error;
use crate::header::FixedHeader;
use crate::packet::PacketType;
use bytes::BytesMut;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Disconnect {}

impl Decode for Disconnect {
    fn decode(packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() == PacketType::Disconnect && packet.header.flags() == 0 {
            Ok(Disconnect::default())
        } else {
            Err(Error::MalformedPacket)
        }
    }
}

impl Encode for Disconnect {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::Disconnect, 0, 0);
        header.encode(buf)
    }

    fn packet_len(&self) -> usize {
        2
    }

    fn payload_len(&self) -> usize {
        // No payload
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    #[test]
    fn disconnect_decode() {
        let mut codec = PacketCodec::new(None, None);

        let data = &[
            (PacketType::Disconnect as u8) << 4, // Packet type
            0x00,                                // Remaining len
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = Disconnect::decode(raw_packet).unwrap();

        assert_eq!(packet, Disconnect::default());
    }

    #[test]
    fn disconnect_encode() {
        let packet = Disconnect::default();

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(stream, vec![(PacketType::Disconnect as u8) << 4, 0x00]);
    }
}
