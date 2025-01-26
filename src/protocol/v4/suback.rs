use crate::Error;
use crate::QoS;

pub(crate) mod inner {
    use crate::codec::util::decode_word;
    use crate::codec::{Decode, Encode, RawPacket};
    use crate::protocol::payload::Codes;
    use crate::protocol::{FixedHeader, PacketType};
    use crate::Error;
    use bytes::{BufMut, BytesMut};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct SubAck<T> {
        packet_id: u16,
        codes: Codes<T>,
    }

    impl<T> SubAck<T>
    where
        T: TryFrom<u8, Error = Error> + Into<u8> + Copy,
    {
        pub fn new<I: IntoIterator<Item = T>>(packet_id: u16, codes: I) -> Self {
            if packet_id == 0 {
                panic!("Packet id is zero");
            }

            let codes: Codes<T> = Codes::new(codes);

            SubAck { packet_id, codes }
        }

        pub fn codes(&self) -> Codes<T> {
            self.codes.clone()
        }

        pub fn packet_id(&self) -> u16 {
            self.packet_id
        }
    }
    impl<T> Decode for SubAck<T>
    where
        T: TryFrom<u8, Error = Error> + Into<u8> + Copy,
    {
        fn decode(mut packet: RawPacket) -> Result<Self, Error> {
            if packet.header.packet_type() != PacketType::SubAck
                || !packet.header.flags().is_default()
            {
                return Err(Error::MalformedPacket);
            }

            let packet_id = decode_word(&mut packet.payload)?;

            // 'remaining len' is always at least 2
            let codes: Codes<T> =
                Codes::decode(&mut packet.payload, packet.header.remaining_len() - 2)?;

            Ok(SubAck { packet_id, codes })
        }
    }

    impl<T> Encode for SubAck<T>
    where
        T: TryFrom<u8, Error = Error> + Into<u8> + Copy,
    {
        fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
            let header = FixedHeader::new(PacketType::SubAck, self.payload_len());
            header.encode(buf)?;

            buf.put_u16(self.packet_id);
            self.codes.encode(buf);
            Ok(())
        }

        fn payload_len(&self) -> usize {
            2 + self.codes.len()
        }
    }
}

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

pub type SubAck = inner::SubAck<ReturnCode>;

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
