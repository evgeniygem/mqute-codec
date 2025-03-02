use super::util;
use crate::protocol::PacketType;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PingReq {}

util::header_packet_decode_impl!(PingReq, PacketType::PingReq);
util::header_packet_encode_impl!(PingReq, PacketType::PingReq);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PingResp {}

util::header_packet_decode_impl!(PingResp, PacketType::PingResp);
util::header_packet_encode_impl!(PingResp, PacketType::PingResp);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use crate::codec::{Decode, Encode};
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
