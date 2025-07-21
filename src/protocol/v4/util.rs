macro_rules! id_packet {
    ($packet:ident) => {
        #[doc = concat!("Represents the packet ID `", stringify!($packet), "` packet")]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $packet {
            packet_id: u16,
        }

        impl $packet {
            /// Creates a new packet.
            ///
            /// # Example
            ///
            /// ```rust
            /// use mqute_codec::protocol::v4::PubAck;
            /// let packet = PubAck::new(1024);
            /// ```
            pub fn new(packet_id: u16) -> Self {
                if packet_id == 0 {
                    panic!("Packet id is zero");
                }

                $packet { packet_id }
            }

            /// Returns the packet ID of the packet.
            ///
            /// # Example
            ///
            /// ```rust
            /// use mqute_codec::protocol::v4::PubAck;
            ///
            /// let packet = PubAck::new(1024);
            /// assert_eq!(packet.packet_id(), 1024);
            /// ```
            pub fn packet_id(&self) -> u16 {
                self.packet_id
            }
        }
    };
}

macro_rules! id_packet_decode_impl {
    ($packet:ident, $packet_type: expr) => {
        impl $crate::codec::Decode for $packet {
            fn decode(mut packet: $crate::codec::RawPacket) -> Result<Self, $crate::Error> {
                if packet.header.packet_type() != $packet_type
                    || !packet.header.flags().is_default()
                {
                    return Err($crate::Error::MalformedPacket);
                }
                let packet_id = $crate::codec::util::decode_word(&mut packet.payload)?;
                Ok($packet::new(packet_id))
            }
        }
    };
}

macro_rules! id_packet_encode_impl {
    ($packet:ident, $packet_type:expr) => {
        use bytes::BufMut;

        impl $crate::codec::Encode for $packet {
            fn encode(&self, buf: &mut bytes::BytesMut) -> Result<(), $crate::Error> {
                let header = $crate::protocol::FixedHeader::new($packet_type, self.payload_len());
                header.encode(buf)?;

                buf.put_u16(self.packet_id);
                Ok(())
            }

            fn payload_len(&self) -> usize {
                2
            }
        }
    };
}

macro_rules! header_packet_decode_impl {
    ($packet:ident, $packet_type:expr) => {
        impl $crate::codec::Decode for $packet {
            fn decode(packet: $crate::codec::RawPacket) -> Result<Self, $crate::Error> {
                if packet.header.packet_type() == $packet_type && packet.header.flags().is_default()
                {
                    Ok($packet {})
                } else {
                    Err($crate::Error::MalformedPacket)
                }
            }
        }
    };
}

macro_rules! header_packet_encode_impl {
    ($packet:ident, $packet_type:expr) => {
        impl $crate::codec::Encode for $packet {
            fn encode(&self, buf: &mut bytes::BytesMut) -> Result<(), $crate::Error> {
                let header = $crate::protocol::FixedHeader::new($packet_type, 0);
                header.encode(buf)
            }

            fn payload_len(&self) -> usize {
                // No payload
                0
            }
        }
    };
}

pub(crate) use header_packet_decode_impl;
pub(crate) use header_packet_encode_impl;
pub(crate) use id_packet;
pub(crate) use id_packet_decode_impl;
pub(crate) use id_packet_encode_impl;
