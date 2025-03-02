use crate::codec::util::{decode_byte, decode_string, decode_word, encode_string};
use crate::protocol::Protocol;
use crate::Error;
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

macro_rules! connect {
    ($name:ident <$property:ident, $will:ident>, $proto:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            header: $crate::protocol::common::ConnectHeader<$property>,
            payload: $crate::protocol::ConnectPayload<$will>,
        }

        const CLEAN_SESSION: usize = 1;

        impl $name {
            fn from_scratch<S: Into<String>>(
                client_id: S,
                auth: Option<$crate::protocol::Auth>,
                will: Option<$will>,
                properties: Option<$property>,
                keep_alive: u16,
                clean_session: bool,
            ) -> Self {
                use bit_field::BitField;
                use $crate::protocol::common::frame::WillFrame;

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
                let payload = $crate::protocol::ConnectPayload::<$will>::new(client_id, auth, will);

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

            pub fn auth(&self) -> Option<$crate::protocol::Auth> {
                self.payload.auth.clone()
            }

            pub fn will(&self) -> Option<$will> {
                self.payload.will.clone()
            }
        }

        impl $crate::codec::Encode for $name {
            fn encode(&self, buf: &mut bytes::BytesMut) -> Result<(), $crate::Error> {
                use $crate::protocol::common::frame::ConnectFrame;

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
                use $crate::protocol::common::frame::ConnectFrame;
                self.header.encoded_len() + self.payload.encoded_len()
            }
        }

        impl $crate::codec::Decode for $name {
            fn decode(mut packet: $crate::codec::RawPacket) -> Result<Self, $crate::Error> {
                use $crate::protocol::common::frame::ConnectFrame;

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
                let payload = $crate::protocol::ConnectPayload::<$will>::decode(
                    &mut packet.payload,
                    header.flags,
                )?;

                Ok(Self { header, payload })
            }
        }
    };
}

pub(crate) use connect;
