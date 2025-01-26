use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::payload::ConnectPayload;
use crate::protocol::variable::ConnectHeader;
use crate::protocol::Protocol;
use crate::protocol::{Auth, FixedHeader, PacketType, Will};
use crate::Error;
use bit_field::BitField;
use bytes::BytesMut;

const CLEAN_SESSION_POSITION: usize = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Connect {
    header: ConnectHeader,
    payload: ConnectPayload,
}

impl Connect {
    pub fn new<T: Into<String>>(
        protocol: Protocol,
        client_id: T,
        auth: Option<Auth>,
        will: Option<Will>,
        keep_alive: u16,
        clean_session: bool,
    ) -> Self {
        if protocol == Protocol::V5 {
            panic!("Unsupported protocol");
        }

        let mut flags = 0u8;

        flags.set_bit(CLEAN_SESSION_POSITION, clean_session);

        if let Some(auth) = auth.as_ref() {
            auth.update_flags(&mut flags);
        }

        if let Some(will) = will.as_ref() {
            will.update_flags(&mut flags);
        }

        let header = ConnectHeader::new(protocol, flags, keep_alive);
        let payload = ConnectPayload::new(client_id, auth, will);

        Connect { header, payload }
    }

    pub fn protocol(&self) -> Protocol {
        self.header.protocol
    }

    pub fn keep_alive(&self) -> u16 {
        self.header.keep_alive
    }

    pub fn clean_session(&self) -> bool {
        self.header.flags.get_bit(CLEAN_SESSION_POSITION)
    }

    pub fn client_id(&self) -> String {
        self.payload.client_id.clone()
    }

    pub fn auth(&self) -> Option<Auth> {
        self.payload.auth.clone()
    }

    pub fn will(&self) -> Option<Will> {
        self.payload.will.clone()
    }
}

impl Decode for Connect {
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::Connect || !packet.header.flags().is_default()
        {
            return Err(Error::MalformedPacket);
        }

        let header = ConnectHeader::decode(&mut packet.payload)?;

        if header.protocol == Protocol::V5 {
            return Err(Error::ProtocolMismatch);
        }

        let payload = ConnectPayload::decode(&mut packet.payload, header.flags)?;

        Ok(Connect { header, payload })
    }
}

impl Encode for Connect {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::Connect, self.payload_len());

        // Encode fixed header
        header.encode(buf)?;

        // Encode variable header
        self.header.encode(buf);

        // Encode payload
        self.payload.encode(buf);

        Ok(())
    }

    fn payload_len(&self) -> usize {
        let len = 2 + self.header.protocol.name().len() + // Protocol name string
            1 +                                                 // Protocol level
            1 +                                                 // Connect flags
            2 +                                                 // Keep alive
            2 + self.payload.client_id.len() +                  // Client ID
            self.payload.will                                   // WillFlag
                .as_ref()
                .map(|will| will.encoded_len())
                .unwrap_or(0) +
            self.payload.auth                                   // Auth
                .as_ref()
                .map(|auth| auth.encoded_len())
                .unwrap_or(0);
        len
    }
}

macro_rules! connect_impl {
    ($packet:ident, $proto:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $packet {
            inner: $crate::protocol::common::Connect,
        }

        impl $packet {
            pub fn new<T: Into<String>>(
                client_id: T,
                auth: Option<$crate::protocol::Auth>,
                will: Option<$crate::protocol::Will>,
                keep_alive: u16,
                clean_session: bool,
            ) -> Self {
                Self {
                    inner: $crate::protocol::common::Connect::new(
                        $proto,
                        client_id,
                        auth,
                        will,
                        keep_alive,
                        clean_session,
                    ),
                }
            }

            pub fn protocol(&self) -> $crate::protocol::Protocol {
                self.inner.protocol()
            }

            pub fn keep_alive(&self) -> u16 {
                self.inner.keep_alive()
            }

            pub fn clean_session(&self) -> bool {
                self.inner.clean_session()
            }

            pub fn client_id(&self) -> String {
                self.inner.client_id()
            }

            pub fn auth(&self) -> Option<$crate::protocol::Auth> {
                self.inner.auth()
            }

            pub fn will(&self) -> Option<$crate::protocol::Will> {
                self.inner.will()
            }
        }

        impl $crate::codec::Encode for $packet {
            fn encode(&self, buf: &mut bytes::BytesMut) -> Result<(), $crate::Error> {
                self.inner.encode(buf)
            }

            fn payload_len(&self) -> usize {
                self.inner.payload_len()
            }
        }

        impl $crate::codec::Decode for $packet {
            fn decode(packet: $crate::codec::RawPacket) -> Result<Self, $crate::Error> {
                let packet = $crate::protocol::common::Connect::decode(packet)?;
                if packet.protocol() != $proto {
                    return Err($crate::Error::ProtocolNotSupported);
                }
                Ok($packet { inner: packet })
            }
        }
    };
}

pub(crate) use connect_impl;
