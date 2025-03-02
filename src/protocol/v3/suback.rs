use crate::protocol::common::suback;
use crate::protocol::QoS;

suback!(SubAck, QoS);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Decode, Encode, PacketCodec};
    use crate::protocol::PacketType;
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    #[test]
    fn suback_decode() {
        let mut codec = PacketCodec::new(None, None);

        let data = &[
            (PacketType::SubAck as u8) << 4, // Packet type
            0x05,                            // Remaining len
            0x12,                            // Packet ID
            0x34,
            0x00, // QoS 0
            0x01, // QoS 1
            0x02, // QoS 2
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = SubAck::decode(raw_packet).unwrap();

        assert_eq!(
            packet,
            SubAck::new(
                0x1234,
                vec![QoS::AtMostOnce, QoS::AtLeastOnce, QoS::ExactlyOnce]
            )
        );
    }

    #[test]
    fn suback_encode() {
        let packet = SubAck::new(
            0x1234,
            vec![QoS::AtMostOnce, QoS::AtLeastOnce, QoS::ExactlyOnce],
        );

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(
            stream,
            vec![
                (PacketType::SubAck as u8) << 4,
                0x05,
                0x12,
                0x34,
                0x00, // QoS 0
                0x01, // QoS 1
                0x02, // QoS 2
            ]
        );
    }
}
