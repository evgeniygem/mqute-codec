use crate::codec::util::{decode_byte, decode_string, decode_word, encode_string};
use crate::protocol::common::frame::WillFrame;
use crate::protocol::Protocol;
use crate::Error;
use bit_field::BitField;
use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectHeader<T> {
    pub protocol: Protocol,
    pub flags: u8,
    pub keep_alive: u16,
    pub properties: Option<T>,
}

impl<T> ConnectHeader<T> {
    pub(crate) fn new(
        protocol: Protocol,
        flags: u8,
        keep_alive: u16,
        properties: Option<T>,
    ) -> Self {
        ConnectHeader {
            protocol,
            flags,
            keep_alive,
            properties,
        }
    }

    pub(crate) fn primary_encoded_len(&self) -> usize {
        2 + self.protocol.name().len() // Protocol name string
            + 1                        // Protocol level
            + 1                        // Connect flags
            + 2 // Keep alive
    }

    pub(crate) fn primary_encode(&self, buf: &mut BytesMut) {
        // Encode the protocol name
        encode_string(buf, self.protocol.name());

        // Add the protocol level
        buf.put_u8(self.protocol.into());

        // Add the flags
        buf.put_u8(self.flags);

        // Add the keep alive timeout
        buf.put_u16(self.keep_alive);
    }

    pub(crate) fn primary_decode(buf: &mut Bytes) -> Result<Self, Error> {
        let protocol_name = decode_string(buf)?;

        let protocol: Protocol = buf.get_u8().try_into()?;

        if protocol_name != protocol.name() {
            return Err(Error::InvalidProtocolName(protocol_name));
        }

        let flags = decode_byte(buf)?;
        let keep_alive = decode_word(buf)?;

        Ok(ConnectHeader {
            protocol,
            flags,
            keep_alive,
            properties: None,
        })
    }
}

const PASSWORD: usize = 6;
const USERNAME: usize = 7;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    username: String,
    password: Option<String>,
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

    pub fn username(&self) -> String {
        self.username.clone()
    }

    pub fn password(&self) -> Option<String> {
        self.password.clone()
    }

    pub(crate) fn encoded_len(&self) -> usize {
        let mut size = 2 + self.username.len();
        if let Some(password) = self.password.as_ref() {
            size += 2 + password.len();
        }
        size
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        encode_string(buf, &self.username);

        if let Some(password) = self.password.as_ref() {
            encode_string(buf, password);
        }
    }

    pub(crate) fn update_flags(&self, flags: &mut u8) {
        // Update username flag
        flags.set_bit(USERNAME, true);

        // Update password flag
        flags.set_bit(PASSWORD, self.password.is_some());
    }

    pub(crate) fn decode(buf: &mut Bytes, flags: u8) -> Result<Option<Self>, Error> {
        if !flags.get_bit(USERNAME) {
            return Ok(None);
        }

        let username = decode_string(buf)?;

        let password = if flags.get_bit(PASSWORD) {
            Some(decode_string(buf)?)
        } else {
            None
        };

        Ok(Some(Auth::new(username, password)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectPayload<T> {
    pub client_id: String,
    pub auth: Option<Auth>,
    pub will: Option<T>,
}

impl<T> ConnectPayload<T>
where
    T: WillFrame,
{
    pub(crate) fn new<S: Into<String>>(client_id: S, auth: Option<Auth>, will: Option<T>) -> Self {
        ConnectPayload {
            client_id: client_id.into(),
            auth,
            will,
        }
    }

    pub(crate) fn decode(payload: &mut Bytes, flags: u8) -> Result<Self, Error> {
        let client_id = decode_string(payload)?;

        let will = T::decode(payload, flags)?;
        let auth = Auth::decode(payload, flags)?;

        Ok(ConnectPayload {
            client_id,
            auth,
            will,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        // Encode the client id
        encode_string(buf, &self.client_id);

        if let Some(will) = self.will.as_ref() {
            will.encode(buf)?;
        }

        if let Some(auth) = self.auth.as_ref() {
            auth.encode(buf);
        }

        Ok(())
    }

    pub(crate) fn encoded_len(&self) -> usize {
        2 + self.client_id.len() +            // Client ID
            self.will                         // WillFlag
                .as_ref()
                .map(|will| will.encoded_len())
                .unwrap_or(0) +
            self.auth                         // Auth
                .as_ref()
                .map(|auth| auth.encoded_len())
                .unwrap_or(0)
    }
}

macro_rules! connect {
    ($name:ident <$property:ident, $will:ident>, $proto:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            header: $crate::protocol::common::ConnectHeader<$property>,
            payload: $crate::protocol::common::ConnectPayload<$will>,
        }

        const CLEAN_SESSION: usize = 1;

        impl $name {
            fn from_scratch<S: Into<String>>(
                client_id: S,
                auth: Option<$crate::protocol::common::Auth>,
                will: Option<$will>,
                properties: Option<$property>,
                keep_alive: u16,
                clean_session: bool,
            ) -> Self {
                use bit_field::BitField;
                use $crate::protocol::common::WillFrame;

                let mut flags = 0u8;

                flags.set_bit(CLEAN_SESSION, clean_session);

                if let Some(auth) = auth.as_ref() {
                    auth.update_flags(&mut flags);
                }

                if let Some(will) = will.as_ref() {
                    will.update_flags(&mut flags);
                }

                let header = $crate::protocol::common::ConnectHeader::<$property>::new(
                    $proto, flags, keep_alive, properties,
                );
                let payload =
                    $crate::protocol::common::ConnectPayload::<$will>::new(client_id, auth, will);

                Self { header, payload }
            }

            pub fn new<S: Into<String>>(
                client_id: S,
                auth: Option<$crate::protocol::Auth>,
                will: Option<$will>,
                keep_alive: u16,
                clean_session: bool,
            ) -> Self {
                Self::from_scratch(client_id, auth, will, None, keep_alive, clean_session)
            }

            pub fn protocol(&self) -> $crate::protocol::Protocol {
                self.header.protocol
            }

            pub fn keep_alive(&self) -> u16 {
                self.header.keep_alive
            }

            pub fn clean_session(&self) -> bool {
                use bit_field::BitField;
                self.header.flags.get_bit(CLEAN_SESSION)
            }

            pub fn client_id(&self) -> String {
                self.payload.client_id.clone()
            }

            pub fn auth(&self) -> Option<$crate::protocol::common::Auth> {
                self.payload.auth.clone()
            }

            pub fn will(&self) -> Option<$will> {
                self.payload.will.clone()
            }
        }

        impl $crate::codec::Encode for $name {
            fn encode(&self, buf: &mut bytes::BytesMut) -> Result<(), $crate::Error> {
                use $crate::protocol::common::ConnectFrame;

                let header = $crate::protocol::FixedHeader::new(
                    $crate::protocol::PacketType::Connect,
                    self.payload_len(),
                );

                // Encode fixed header
                header.encode(buf)?;

                // Encode variable header
                self.header.encode(buf)?;

                // Encode payload
                self.payload.encode(buf)
            }

            fn payload_len(&self) -> usize {
                use $crate::protocol::common::ConnectFrame;
                self.header.encoded_len() + self.payload.encoded_len()
            }
        }

        impl $crate::codec::Decode for $name {
            fn decode(mut packet: $crate::codec::RawPacket) -> Result<Self, $crate::Error> {
                use $crate::protocol::common::ConnectFrame;

                if packet.header.packet_type() != $crate::protocol::PacketType::Connect
                    || !packet.header.flags().is_default()
                {
                    return Err($crate::Error::MalformedPacket);
                }

                let header = $crate::protocol::common::ConnectHeader::<$property>::decode(
                    &mut packet.payload,
                )?;

                if header.protocol != $proto {
                    return Err($crate::Error::ProtocolNotSupported);
                }
                let payload = $crate::protocol::common::ConnectPayload::<$will>::decode(
                    &mut packet.payload,
                    header.flags,
                )?;

                Ok(Self { header, payload })
            }
        }
    };
}

pub(crate) use connect;
