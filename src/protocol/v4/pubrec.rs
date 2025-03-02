use super::util;
use crate::protocol::PacketType;

// Create 'PubRec' packet
util::id_packet!(PubRec);

// Implement decode
util::id_packet_decode_impl!(PubRec, PacketType::PubRec);

// Implement encode
util::id_packet_encode_impl!(PubRec, PacketType::PubRec);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use crate::codec::{Decode, Encode};
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
