macro_rules! suback {
    ($packet:ident, $code:ty) => {
        use bytes::BufMut;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct SubAck {
            packet_id: u16,
            codes: $crate::protocol::payload::Codes<$code>,
        }

        impl SubAck {
            pub fn new<I: IntoIterator<Item = $code>>(packet_id: u16, codes: I) -> Self {
                if packet_id == 0 {
                    panic!("Packet id is zero");
                }

                let codes = $crate::protocol::payload::Codes::new(codes);

                SubAck { packet_id, codes }
            }

            pub fn codes(&self) -> $crate::protocol::payload::Codes<$code> {
                self.codes.clone()
            }

            pub fn packet_id(&self) -> u16 {
                self.packet_id
            }
        }
        impl $crate::codec::Decode for SubAck {
            fn decode(mut packet: $crate::codec::RawPacket) -> Result<Self, $crate::Error> {
                if packet.header.packet_type() != $crate::protocol::PacketType::SubAck
                    || !packet.header.flags().is_default()
                {
                    return Err($crate::Error::MalformedPacket);
                }

                let packet_id = $crate::codec::util::decode_word(&mut packet.payload)?;

                // 'remaining len' is always at least 2
                let codes = $crate::protocol::payload::Codes::decode(&mut packet.payload)?;

                Ok(SubAck { packet_id, codes })
            }
        }

        impl $crate::codec::Encode for SubAck {
            fn encode(&self, buf: &mut bytes::BytesMut) -> Result<(), $crate::Error> {
                let header = $crate::protocol::FixedHeader::new(
                    $crate::protocol::PacketType::SubAck,
                    self.payload_len(),
                );
                header.encode(buf)?;

                buf.put_u16(self.packet_id);
                self.codes.encode(buf);
                Ok(())
            }

            fn payload_len(&self) -> usize {
                2 + self.codes.len()
            }
        }
    };
}

pub(crate) use suback;
