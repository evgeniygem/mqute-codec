//! # PubRel Packet V4
//!
//! This module defines the `PubRel` packet, which is used in the MQTT protocol as part of the
//! QoS 2 message flow. The `PubRel` packet is sent by the publisher to acknowledge the receipt
//! of a `PUBREC` packet and to indicate that the message can be released to subscribers.

use super::util;
use crate::codec::util::decode_word;
use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::{FixedHeader, Flags, PacketType, QoS};
use crate::Error;
use bytes::BufMut;

// Defines the `PubRel` packet for MQTT V4
util::id_packet!(PubRel);

impl Encode for PubRel {
    /// Encodes the `PubRel` packet into a byte buffer.
    fn encode(&self, buf: &mut bytes::BytesMut) -> Result<(), Error> {
        let header = FixedHeader::with_flags(
            PacketType::PubRel,
            Flags::new(QoS::AtLeastOnce),
            self.payload_len(),
        );
        header.encode(buf)?;

        buf.put_u16(self.packet_id);
        Ok(())
    }

    /// Returns the length of the `PubRel` packet payload.
    fn payload_len(&self) -> usize {
        2
    }
}

impl Decode for PubRel {
    /// Decodes a `PubRel` packet from a raw MQTT packet.
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::PubRel
            || packet.header.flags() != Flags::new(QoS::AtLeastOnce)
        {
            return Err(Error::MalformedPacket);
        }
        let packet_id = decode_word(&mut packet.payload)?;
        Ok(PubRel::new(packet_id))
    }
}

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
            (PacketType::PubRel as u8) << 4 | 0b0010, // Packet type
            0x02,                                     // Remaining len
            0x12,                                     // Packet ID
            0x34,
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = PubRel::decode(raw_packet).unwrap();

        assert_eq!(packet, PubRel::new(0x1234));
    }

    #[test]
    fn pubrel_encode() {
        let packet = PubRel::new(0x1234);

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(
            stream,
            vec![(PacketType::PubRel as u8) << 4 | 0b0010, 0x02, 0x12, 0x34]
        );
    }
}
