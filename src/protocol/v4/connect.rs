use crate::codec::util::{decode_bytes, decode_string, encode_bytes, encode_string};
use crate::codec::{Decode, Encode, RawPacket};
use crate::error::Error;
use crate::header::FixedHeader;
use crate::packet::PacketType;
use crate::qos::QoS;
use crate::Protocol;
use bit_field::BitField;
use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Flag {
    CleanSession = 1,
    WillFlag = 2,
    WillQosBegin = 3,
    WillQosEnd = 4,
    WillRetain = 5,
    Password = 6,
    Username = 7,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    pub username: String,
    pub password: Option<String>,
}

impl Auth {
    pub fn new<T>(username: T, password: Option<String>) -> Self
    where
        T: Into<String>,
    {
        Auth {
            username: username.into(),
            password,
        }
    }

    pub fn with_name<T: Into<String>>(username: T) -> Self {
        Self::new(username, None)
    }

    pub fn login<T: Into<String>, U: Into<String>>(username: T, password: U) -> Self {
        Self::new(username.into(), Some(password.into()))
    }

    pub fn set_password<T: Into<String>>(&mut self, password: T) {
        self.password = Some(password.into());
    }

    fn payload_len(&self) -> usize {
        let mut size = 2 + self.username.len();
        if let Some(password) = self.password.as_ref() {
            size += 2 + password.len();
        }
        size
    }

    fn encode(&self, buf: &mut BytesMut, flags: &mut u8) {
        encode_string(buf, &self.username);

        // Update username flag
        flags.set_bit(Flag::Username as usize, true);

        if let Some(password) = self.password.as_ref() {
            encode_string(buf, password);

            // Update password flag
            flags.set_bit(Flag::Password as usize, true);
        }
    }

    fn decode(flags: u8, buf: &mut Bytes) -> Result<Option<Self>, Error> {
        if !flags.get_bit(Flag::Username as usize) {
            return Ok(None);
        }

        let username = decode_string(buf)?;

        let password = if flags.get_bit(Flag::Password as usize) {
            Some(decode_string(buf)?)
        } else {
            None
        };

        Ok(Some(Auth::new(username, password)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Will {
    topic: String,
    message: Bytes,
    qos: QoS,
    retain: bool,
}

impl Will {
    pub fn new<T: Into<String>>(topic: T, message: Bytes, qos: QoS, retain: bool) -> Self {
        Will {
            topic: topic.into(),
            message,
            qos,
            retain,
        }
    }

    fn payload_len(&self) -> usize {
        2 + self.topic.len() + 2 + self.message.len()
    }

    fn encode(&self, buf: &mut BytesMut, flags: &mut u8) {
        // Update the 'Will' flag
        flags.set_bit(Flag::WillFlag as usize, true);
        let qos_range = (Flag::WillQosBegin as usize)..=(Flag::WillQosEnd as usize);

        // Update 'Qos' flags
        flags.set_bits(qos_range, self.qos as u8);

        // Update the 'Will Retain' flag
        flags.set_bit(Flag::WillRetain as usize, self.retain);

        encode_string(buf, &self.topic);
        encode_bytes(buf, &self.message);
    }

    fn decode(flags: u8, buf: &mut Bytes) -> Result<Option<Self>, Error> {
        if !flags.get_bit(Flag::WillFlag as usize) {
            // No 'Will'
            return Ok(None);
        }

        let qos_range = (Flag::WillQosBegin as usize)..=(Flag::WillQosEnd as usize);
        let qos = flags.get_bits(qos_range).try_into()?;

        let retain = flags.get_bit(Flag::WillRetain as usize);

        let topic = decode_string(buf)?;
        let message = decode_bytes(buf)?;
        Ok(Some(Will::new(topic, message, qos, retain)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect {
    client_id: String,
    auth: Option<Auth>,
    will: Option<Will>,
    keep_alive: u16,
    clean_session: bool,
}

impl Connect {
    pub fn new<T: Into<String>>(
        client_id: T,
        auth: Option<Auth>,
        will: Option<Will>,
        keep_alive: u16,
        clean_session: bool,
    ) -> Self {
        Connect {
            client_id: client_id.into(),
            auth,
            will,
            keep_alive,
            clean_session,
        }
    }
}

impl Decode for Connect {
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::Connect || packet.header.flags() != 0 {
            return Err(Error::MalformedPacket);
        }

        let protocol_name = decode_string(&mut packet.payload)?;
        if protocol_name != Protocol::V4.name() {
            return Err(Error::InvalidProtocolName(protocol_name));
        }
        let protocol_level = packet.payload.get_u8();
        if protocol_level != Protocol::V4.into() {
            return Err(Error::InvalidProtocolLevel(protocol_level));
        }

        let flags = packet.payload.get_u8();
        let keep_alive = packet.payload.get_u16();

        let client_id = decode_string(&mut packet.payload)?;

        let clean_session = flags.get_bit(Flag::CleanSession as usize);
        let will = Will::decode(flags, &mut packet.payload)?;
        let auth = Auth::decode(flags, &mut packet.payload)?;

        let packet = Connect {
            client_id,
            auth,
            will,
            keep_alive,
            clean_session,
        };
        Ok(packet)
    }
}

impl Encode for Connect {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::Connect, 0, self.payload_len());
        let mut flags = 0u8;

        header.encode(buf)?;

        // Encode the protocol name
        encode_string(buf, Protocol::V4.name());

        // Add the protocol level
        buf.put_u8(Protocol::V4.into());

        // Add the flags
        buf.put_u8(flags);

        // Add the keep alive timeout
        buf.put_u16(self.keep_alive);

        // Encode the client id
        encode_string(buf, &self.client_id);

        flags.set_bit(Flag::CleanSession as usize, self.clean_session);

        if let Some(will) = self.will.as_ref() {
            will.encode(buf, &mut flags);
        }

        if let Some(auth) = self.auth.as_ref() {
            auth.encode(buf, &mut flags);
        }

        // Update flags
        let flags_index = header.fixed_len() + 2 + Protocol::V4.name().len() + 1;
        buf[flags_index] = flags;

        Ok(())
    }

    fn payload_len(&self) -> usize {
        let len = 2 + Protocol::V4.name().len() + // Protocol name string
            1 +                                         // Protocol level
            1 +                                         // Connect flags
            2 +                                         // Keep alive
            2 + self.client_id.len() +                  // Client ID
            self.will                                   // WillFlag
                .as_ref()
                .map(|will| will.payload_len())
                .unwrap_or(0) +
            self.auth                                   // Auth
                .as_ref()
                .map(|auth| auth.payload_len())
                .unwrap_or(0);
        len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    #[test]
    fn connect_decode() {
        let mut codec = PacketCodec::new(None, None);

        let data = &[
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
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = Connect::decode(raw_packet).unwrap();

        let auth = Some(Auth::login("user", "pass"));
        let will = Some(Will::new(
            "/abc",
            Bytes::from("bye"),
            QoS::ExactlyOnce,
            false,
        ));

        assert_eq!(packet, Connect::new("client", auth, will, 16, true));
    }

    #[test]
    fn connect_encode() {
        let auth = Some(Auth::login("user", "pass"));
        let will = Some(Will::new(
            "/abc",
            Bytes::from("bye"),
            QoS::ExactlyOnce,
            false,
        ));

        let packet = Connect::new("client", auth, will, 16, true);

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(
            stream,
            vec![
                (PacketType::Connect as u8) << 4, // Packet type
                0x29,                             // Remaining len
                0x00,                             // Protocol name
                0x04,
                b'M',
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
        );
    }
}
