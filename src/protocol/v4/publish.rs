use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::variable::PublishHeader;
use crate::protocol::{FixedHeader, Flags, PacketType};
use crate::Error;
use crate::QoS;
use bytes::{Bytes, BytesMut};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    header: PublishHeader,
    payload: Bytes,
    qos: QoS,
    dup: bool,
    retain: bool,
}

impl Publish {
    pub fn new<T: Into<String>>(topic: T, payload: Bytes, packet_id: u16, flags: Flags) -> Self {
        if flags.qos != QoS::AtMostOnce && packet_id == 0 {
            panic!("Control packets must contain a non-zero packet identifier at QoS > 0");
        }

        Publish {
            header: PublishHeader::new(topic, packet_id),
            payload,
            qos: flags.qos,
            dup: flags.dup,
            retain: flags.retain,
        }
    }
}

impl Decode for Publish {
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::Publish {
            return Err(Error::MalformedPacket);
        }

        let flags = packet.header.flags();

        let publish_header = PublishHeader::decode(&mut packet.payload, flags.qos)?;

        let packet = Publish {
            header: publish_header,
            payload: packet.payload,
            qos: flags.qos,
            dup: flags.dup,
            retain: flags.retain,
        };
        Ok(packet)
    }
}

impl Encode for Publish {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let flags = Flags {
            dup: self.dup,
            qos: self.qos,
            retain: self.retain,
        };

        let header = FixedHeader::with_flags(PacketType::Publish, flags, self.payload_len());
        header.encode(buf)?;
        self.header.encode(buf, self.qos);

        // Append message
        buf.extend_from_slice(&self.payload);
        Ok(())
    }

    fn payload_len(&self) -> usize {
        let packet_id_len = if self.qos == QoS::AtMostOnce { 0 } else { 2 };
        2 + self.header.topic.len() + self.payload.len() + packet_id_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use crate::QoS;
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    #[test]
    fn publish_decode() {
        let mut codec = PacketCodec::new(None, None);

        let payload: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        let data = &[
            (PacketType::Publish as u8) << 4 | 0b0000_0100, // Packet type
            0x0d,                                           // Remaining len
            0x00,
            0x05,
            b'/',
            b't',
            b'e',
            b's',
            b't',
            0x12,
            0x34,
            0xde,
            0xad,
            0xbe,
            0xef,
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = Publish::decode(raw_packet).unwrap();

        assert_eq!(
            packet,
            Publish::new(
                "/test",
                Bytes::copy_from_slice(&payload),
                0x1234,
                Flags::new(QoS::ExactlyOnce)
            )
        );
    }

    #[test]
    fn publish_encode() {
        let payload: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        let packet = Publish::new(
            "/test",
            Bytes::copy_from_slice(&payload),
            0x1234,
            Flags::new(QoS::ExactlyOnce),
        );

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(
            stream,
            vec![
                (PacketType::Publish as u8) << 4 | 0b0000_0100, // Packet type
                0x0d,                                           // Remaining len
                0x00,
                0x05,
                b'/',
                b't',
                b'e',
                b's',
                b't',
                0x12,
                0x34,
                0xde,
                0xad,
                0xbe,
                0xef,
            ]
        );
    }
}
