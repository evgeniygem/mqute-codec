use crate::protocol::common::suback;
use crate::protocol::QoS;
use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnCode {
    Success(QoS),
    Failure,
}

impl TryFrom<u8> for ReturnCode {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let code = match value {
            0x0 => ReturnCode::Success(QoS::AtMostOnce),
            0x1 => ReturnCode::Success(QoS::AtLeastOnce),
            0x2 => ReturnCode::Success(QoS::ExactlyOnce),
            0x80 => ReturnCode::Failure,
            _ => return Err(Error::InvalidReasonCode(value)),
        };

        Ok(code)
    }
}

impl Into<u8> for ReturnCode {
    fn into(self) -> u8 {
        match self {
            ReturnCode::Success(qos) => qos as u8,
            ReturnCode::Failure => 0x80,
        }
    }
}

suback!(SubAck, ReturnCode);

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
            0x04,                            // Remaining len
            0x12,                            // Packet ID
            0x34,
            0x02, // Success
            0x80, // Failure
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = SubAck::decode(raw_packet).unwrap();

        assert_eq!(
            packet,
            SubAck::new(
                0x1234,
                vec![ReturnCode::Success(QoS::ExactlyOnce), ReturnCode::Failure]
            )
        );
    }

    #[test]
    fn suback_encode() {
        let packet = SubAck::new(
            0x1234,
            vec![ReturnCode::Success(QoS::ExactlyOnce), ReturnCode::Failure],
        );

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(
            stream,
            vec![
                (PacketType::SubAck as u8) << 4,
                0x04,
                0x12,
                0x34,
                0x02,
                0x80
            ]
        );
    }
}
