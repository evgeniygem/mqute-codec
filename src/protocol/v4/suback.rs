use crate::codec::util::decode_word;
use crate::codec::{Decode, Encode, RawPacket};
use crate::error::Error;
use crate::header::FixedHeader;
use crate::packet::PacketType;
use crate::qos::QoS;
use bytes::{Buf, BufMut, BytesMut};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubAck {
    packet_id: u16,
    codes: Vec<ReturnCode>,
}

impl SubAck {
    pub fn new(packet_id: u16, codes: Vec<ReturnCode>) -> Self {
        SubAck { packet_id, codes }
    }
}

impl Decode for SubAck {
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::SubAck || packet.header.flags() != 0 {
            return Err(Error::MalformedPacket);
        }

        let packet_id = decode_word(&mut packet.payload)?;

        // 'remaining len' is always at least 2
        let mut codes = Vec::with_capacity(packet.header.remaining_len() - 2);
        while packet.payload.has_remaining() {
            codes.push(packet.payload.get_u8().try_into()?);
        }

        if codes.is_empty() {
            return Err(Error::NoSubscription);
        }

        Ok(SubAck::new(packet_id, codes))
    }
}

impl Encode for SubAck {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::SubAck, 0, self.payload_len());
        header.encode(buf)?;

        buf.put_u16(self.packet_id);
        self.codes.iter().for_each(|&code| {
            let value = match code {
                ReturnCode::Success(qos) => qos as u8,
                ReturnCode::Failure => 0x80,
            };
            buf.put_u8(value);
        });
        Ok(())
    }

    fn payload_len(&self) -> usize {
        2 + self.codes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
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
