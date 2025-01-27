macro_rules! connect {
    ($packet:ident, $proto:expr) => {
        use bit_field::BitField;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $packet {
            header: $crate::protocol::variable::ConnectHeader,
            payload: $crate::protocol::payload::ConnectPayload,
        }

        const CLEAN_SESSION_POSITION: usize = 1;

        impl $packet {
            pub fn new<T: Into<String>>(
                client_id: T,
                auth: Option<$crate::protocol::Auth>,
                will: Option<$crate::protocol::Will>,
                keep_alive: u16,
                clean_session: bool,
            ) -> Self {
                let mut flags = 0u8;

                flags.set_bit(CLEAN_SESSION_POSITION, clean_session);

                if let Some(auth) = auth.as_ref() {
                    auth.update_flags(&mut flags);
                }

                if let Some(will) = will.as_ref() {
                    will.update_flags(&mut flags);
                }

                let header =
                    $crate::protocol::variable::ConnectHeader::new($proto, flags, keep_alive);
                let payload =
                    $crate::protocol::payload::ConnectPayload::new(client_id, auth, will);

                Self { header, payload }
            }

            pub fn protocol(&self) -> $crate::protocol::Protocol {
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

            pub fn auth(&self) -> Option<$crate::protocol::Auth> {
                self.payload.auth.clone()
            }

            pub fn will(&self) -> Option<$crate::protocol::Will> {
                self.payload.will.clone()
            }
        }

        impl $crate::codec::Encode for $packet {
            fn encode(&self, buf: &mut bytes::BytesMut) -> Result<(), $crate::Error> {
                let header = $crate::protocol::FixedHeader::new(
                    $crate::protocol::PacketType::Connect, self.payload_len());

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
                    1 +                                           // Protocol level
                    1 +                                           // Connect flags
                    2 +                                           // Keep alive
                    2 + self.payload.client_id.len() +            // Client ID
                    self.payload.will                             // WillFlag
                        .as_ref()
                        .map(|will| will.encoded_len())
                        .unwrap_or(0) +
                    self.payload.auth                             // Auth
                        .as_ref()
                        .map(|auth| auth.encoded_len())
                        .unwrap_or(0);
                len
            }
        }

        impl $crate::codec::Decode for $packet {
            fn decode(mut packet: $crate::codec::RawPacket) -> Result<Self, $crate::Error> {
                if packet.header.packet_type() != $crate::protocol::PacketType::Connect
                    || !packet.header.flags().is_default() {
                    return Err($crate::Error::MalformedPacket);
                }

                let header = $crate::protocol::variable::ConnectHeader::decode(
                    &mut packet.payload)?;

                if header.protocol != $proto {
                    return Err($crate::Error::ProtocolNotSupported);
                }
                let payload = $crate::protocol::payload::ConnectPayload::decode(
                    &mut packet.payload, header.flags)?;

                Ok(Self { header, payload })
            }
        }
    };
}

pub(crate) use connect;
