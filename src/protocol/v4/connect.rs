use crate::codec::util::{decode_bytes, decode_string, encode_bytes, encode_string};
use crate::protocol::common::frame::{ConnectFrame, WillFrame};
use crate::protocol::common::{connect, ConnectHeader};
use crate::protocol::Protocol;
use crate::{Error, QoS};
use bit_field::BitField;
use bytes::{Bytes, BytesMut};
use std::ops::RangeInclusive;

const WILL_FLAG: usize = 2;
const WILL_QOS: RangeInclusive<usize> = 3..=4;
const WILL_RETAIN: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Will {
    pub topic: String,
    pub payload: Bytes,
    pub qos: QoS,
    pub retain: bool,
}

impl Will {
    pub fn new<T: Into<String>>(topic: T, payload: Bytes, qos: QoS, retain: bool) -> Self {
        Will {
            topic: topic.into(),
            payload,
            qos,
            retain,
        }
    }
}

impl WillFrame for Will {
    fn encoded_len(&self) -> usize {
        2 + self.topic.len() + 2 + self.payload.len()
    }

    fn update_flags(&self, flags: &mut u8) {
        // Update the 'Will' flag
        flags.set_bit(WILL_FLAG as usize, true);

        // Update 'Qos' flags
        flags.set_bits(WILL_QOS, self.qos as u8);

        // Update the 'Will Retain' flag
        flags.set_bit(WILL_RETAIN, self.retain);
    }

    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        encode_string(buf, &self.topic);
        encode_bytes(buf, &self.payload);
        Ok(())
    }

    fn decode(buf: &mut Bytes, flags: u8) -> Result<Option<Self>, Error> {
        if !flags.get_bit(WILL_FLAG) {
            // No 'Will'
            return Ok(None);
        }

        let qos = flags.get_bits(WILL_QOS).try_into()?;
        let retain = flags.get_bit(WILL_RETAIN);

        let topic = decode_string(buf)?;
        let message = decode_bytes(buf)?;
        Ok(Some(Will::new(topic, message, qos, retain)))
    }
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub(crate) struct Propertyless;

impl ConnectFrame for ConnectHeader<Propertyless> {
    fn encoded_len(&self) -> usize {
        self.primary_encoded_len()
    }

    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        self.primary_encode(buf);
        Ok(())
    }

    fn decode(buf: &mut Bytes) -> Result<Self, Error> {
        Self::primary_decode(buf)
    }
}

connect!(Connect<Propertyless, Will>, Protocol::V4);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use crate::codec::*;
    use crate::protocol::*;
    use crate::QoS;
    use bytes::{Bytes, BytesMut};
    use tokio_util::codec::Decoder;

    fn connect_sample() -> [u8; 43] {
        [
            (PacketType::Connect as u8) << 4, // Packet type
            0x29,                             // Remaining len
            0x00,                             // Protocol name len
            0x04,
            b'M', // Protocol name
            b'Q',
            b'T',
            b'T',
            Protocol::V4.into(), // Protocol level
            0b1101_0110,         // Flags
            0x00,                // Keep alive
            0x10,
            0x00, // Client ID
            0x06,
            b'c',
            b'l',
            b'i',
            b'e',
            b'n',
            b't',
            0x00, // Will topic
            0x04,
            b'/',
            b'a',
            b'b',
            b'c',
            0x00, // Will message
            0x03,
            b'b',
            b'y',
            b'e',
            0x00, // Username
            0x04,
            b'u',
            b's',
            b'e',
            b'r',
            0x00, // Password
            0x04,
            b'p',
            b'a',
            b's',
            b's',
        ]
    }

    fn connect_packet() -> Connect {
        let auth = Some(Auth::login("user", "pass"));
        let will = Some(Will::new(
            "/abc",
            Bytes::from("bye"),
            QoS::ExactlyOnce,
            false,
        ));

        Connect::new("client", auth, will, 16, true)
    }

    #[test]
    fn connect_decode() {
        let mut codec = PacketCodec::new(None, None);

        let mut buf = BytesMut::new();

        buf.extend_from_slice(&connect_sample());

        let raw_packet = codec.decode(&mut buf).unwrap().unwrap();
        let packet = Connect::decode(raw_packet).unwrap();
        assert_eq!(packet, connect_packet());
    }

    #[test]
    fn connect_encode_v4() {
        let packet = connect_packet();
        let mut buf = BytesMut::new();
        packet.encode(&mut buf).unwrap();
        assert_eq!(buf, Vec::from(connect_sample()));
    }
}
