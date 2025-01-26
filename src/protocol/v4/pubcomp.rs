use crate::protocol::common::util;
use crate::protocol::PacketType;

// Create 'PubComp' packet
util::id_packet!(PubComp);

// Implement decode
util::id_packet_decode_impl!(PubComp, PacketType::PubComp);

// Implement encode
util::id_packet_encode_impl!(PubComp, PacketType::PubComp);

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
            (PacketType::PubComp as u8) << 4, // Packet type
            0x02,                             // Remaining len
            0x12,                             // Packet ID
            0x34,
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = PubComp::decode(raw_packet).unwrap();

        assert_eq!(packet, PubComp::new(0x1234));
    }

    #[test]
    fn pubrel_encode() {
        let packet = PubComp::new(0x1234);

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(
            stream,
            vec![(PacketType::PubComp as u8) << 4, 0x02, 0x12, 0x34]
        );
    }
}
