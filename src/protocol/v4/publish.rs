use crate::codec::util::{decode_string, decode_word, encode_string};
use crate::codec::{Decode, Encode, RawPacket};
use crate::error::Error;
use crate::header::FixedHeader;
use crate::packet::PacketType;
use crate::qos::QoS;
use bit_field::BitField;
use bytes::{BufMut, Bytes, BytesMut};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    topic: String,
    payload: Bytes,
    packet_id: u16,
    qos: QoS,
    dup: bool,
    retain: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Flag {
    Retain = 0,
    QosBegin = 1,
    QosEnd = 2,
    Dup = 3,
}

impl Publish {
    pub fn new<T: Into<String>>(topic: T, payload: Bytes, qos: QoS, packet_id: u16) -> Self {
        if qos != QoS::AtMostOnce && packet_id == 0 {
            panic!("Packet id is zero at QoS > 0");
        }

        if qos == QoS::AtMostOnce && packet_id != 0 {
            panic!("Packet id is non-zero at QoS = 0");
        }

        Publish {
            topic: topic.into(),
            payload,
            packet_id,
            qos,
            dup: false,
            retain: false,
        }
    }

    pub fn set_dup(&mut self, flag: bool) {
        self.dup = flag;
    }

    pub fn set_retain(&mut self, flag: bool) {
        self.retain = flag;
    }
}

impl Decode for Publish {
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::Publish {
            return Err(Error::MalformedPacket);
        }

        let flags = packet.header.flags();

        let qos_range = (Flag::QosBegin as usize)..=(Flag::QosEnd as usize);

        let retain = flags.get_bit(Flag::Retain as usize);
        let qos: QoS = flags.get_bits(qos_range).try_into()?;
        let dup = flags.get_bit(Flag::Dup as usize);
        let topic = decode_string(&mut packet.payload)?;

        let packet_id = match qos {
            QoS::AtMostOnce => 0,
            QoS::AtLeastOnce | QoS::ExactlyOnce => decode_word(&mut packet.payload)?,
        };

        if qos != QoS::AtMostOnce && packet_id == 0 {
            return Err(Error::MalformedPacket);
        }

        let packet = Publish {
            topic,
            payload: packet.payload,
            packet_id,
            qos,
            dup,
            retain,
        };
        Ok(packet)
    }
}

impl Encode for Publish {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let mut flags = 0u8;

        // Update the 'Retain' flag
        flags.set_bit(Flag::Retain as usize, self.retain);

        let qos_range = (Flag::QosBegin as usize)..=(Flag::QosEnd as usize);

        // Update 'Qos' flags
        flags.set_bits(qos_range, self.qos as u8);

        // Update the 'dup' flag
        flags.set_bit(Flag::Dup as usize, self.dup);

        let header = FixedHeader::new(PacketType::Publish, flags, self.payload_len());
        header.encode(buf)?;

        encode_string(buf, &self.topic);

        // The Packet Identifier field is only present in PUBLISH Packets where
        // the QoS level is 1 or 2
        if self.qos != QoS::AtMostOnce {
            // 'packet_id' is non-zero
            buf.put_u16(self.packet_id);
        }

        buf.extend_from_slice(&self.payload);
        Ok(())
    }

    fn payload_len(&self) -> usize {
        let packet_id_len = if self.qos == QoS::AtMostOnce { 0 } else { 2 };
        2 + self.topic.len() + self.payload.len() + packet_id_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
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
                QoS::ExactlyOnce,
                0x1234
            )
        );
    }

    #[test]
    fn publish_encode() {
        let payload: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        let packet = Publish::new(
            "/test",
            Bytes::copy_from_slice(&payload),
            QoS::ExactlyOnce,
            0x1234,
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
