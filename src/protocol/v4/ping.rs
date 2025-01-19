use crate::codec::{Decode, Encode, RawPacket};
use crate::error::Error;
use crate::header::FixedHeader;
use crate::packet::PacketType;
use bytes::BytesMut;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PingReq {}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PingResp {}

impl Decode for PingReq {
    fn decode(packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() == PacketType::PingReq && packet.header.flags() == 0 {
            Ok(PingReq::default())
        } else {
            Err(Error::MalformedPacket)
        }
    }
}

impl Encode for PingReq {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::PingReq, 0, 0);
        header.encode(buf)
    }

    fn payload_len(&self) -> usize {
        0
    }

    fn packet_len(&self) -> usize {
        2
    }
}

impl Decode for PingResp {
    fn decode(packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() == PacketType::PingResp && packet.header.flags() == 0 {
            Ok(PingResp::default())
        } else {
            Err(Error::MalformedPacket)
        }
    }
}

impl Encode for PingResp {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::PingResp, 0, 0);
        header.encode(buf)
    }

    fn payload_len(&self) -> usize {
        0
    }

    fn packet_len(&self) -> usize {
        2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    #[test]
    fn pingreq_decode() {
        let mut codec = PacketCodec::new(None, None);

        let data = &[
            (PacketType::PingReq as u8) << 4, // Packet type
            0x00,                             // Remaining len
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = PingReq::decode(raw_packet).unwrap();

        assert_eq!(packet, PingReq::default());
    }

    #[test]
    fn pingreq_encode() {
        let packet = PingReq::default();

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(stream, vec![(PacketType::PingReq as u8) << 4, 0x00]);
    }

    #[test]
    fn pingresp_decode() {
        let mut codec = PacketCodec::new(None, None);

        let data = &[
            (PacketType::PingResp as u8) << 4, // Packet type
            0x00,                              // Remaining len
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = PingResp::decode(raw_packet).unwrap();

        assert_eq!(packet, PingResp::default());
    }

    #[test]
    fn pingresp_encode() {
        let packet = PingResp::default();

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(stream, vec![(PacketType::PingResp as u8) << 4, 0x00]);
    }
}
