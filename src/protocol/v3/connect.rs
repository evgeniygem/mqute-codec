use crate::protocol::common::connect;
use crate::protocol::v4::{Propertyless, Will};
use crate::protocol::Protocol;

connect!(Connect<Propertyless, Will>, Protocol::V3);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use crate::codec::*;
    use crate::protocol::*;
    use crate::QoS;
    use bytes::{Bytes, BytesMut};
    use tokio_util::codec::Decoder;

    fn connect_sample() -> [u8; 45] {
        [
            (PacketType::Connect as u8) << 4, // Packet type
            0x2b,                             // Remaining len
            0x00,                             // Protocol name len
            0x06,
            b'M', // Protocol name
            b'Q',
            b'I',
            b's',
            b'd',
            b'p',
            Protocol::V3.into(), // Protocol level
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
    fn connect_encode() {
        let packet = connect_packet();
        let mut buf = BytesMut::new();
        packet.encode(&mut buf).unwrap();
        assert_eq!(buf, Vec::from(connect_sample()));
    }
}
