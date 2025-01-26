macro_rules! packet {
    ($packet:ident, $connect:ident, $connack:ident,
     $publish:ident, $puback:ident, $pubrec:ident,
     $pubrel:ident, $pubcomp:ident, $subscribe:ident,
     $suback:ident, $unsubscribe:ident, $unsuback:ident,
     $pingreq:ident, $pingresp:ident, $disconnect:ident) => {
        use $crate::codec::{Decode, Encode};
        pub enum $packet {
            Connect($connect),
            ConnAck($connack),
            Publish($publish),
            PubAck($puback),
            PubRec($pubrec),
            PubRel($pubrel),
            PubComp($pubcomp),
            Subscribe($subscribe),
            SubAck($suback),
            Unsubscribe($unsubscribe),
            UnsubAck($unsuback),
            PingReq($pingreq),
            PingResp($pingresp),
            Disconnect($disconnect),
        }

        impl $packet {
            pub fn decode(raw_packet: $crate::codec::RawPacket) -> Result<Self, $crate::Error> {
                let packet_type = raw_packet.header.packet_type();

                if raw_packet.header.remaining_len() == 0 {
                    return match packet_type {
                        $crate::protocol::PacketType::PingReq => {
                            Ok(Self::PingReq($pingreq::decode(raw_packet)?))
                        }
                        $crate::protocol::PacketType::PingResp => {
                            Ok(Self::PingResp($pingresp::decode(raw_packet)?))
                        }
                        $crate::protocol::PacketType::Disconnect => {
                            Ok(Self::Disconnect($disconnect::decode(raw_packet)?))
                        }
                        _ => Err($crate::Error::PayloadRequired),
                    };
                }

                let decoded = match packet_type {
                    $crate::protocol::PacketType::Connect => {
                        Self::Connect($connect::decode(raw_packet)?)
                    }
                    $crate::protocol::PacketType::ConnAck => {
                        Self::ConnAck($connack::decode(raw_packet)?)
                    }
                    $crate::protocol::PacketType::Publish => {
                        Self::Publish($publish::decode(raw_packet)?)
                    }
                    $crate::protocol::PacketType::PubAck => {
                        Self::PubAck($puback::decode(raw_packet)?)
                    }
                    $crate::protocol::PacketType::PubRec => {
                        Self::PubRec($pubrec::decode(raw_packet)?)
                    }
                    $crate::protocol::PacketType::PubRel => {
                        Self::PubRel($pubrel::decode(raw_packet)?)
                    }
                    $crate::protocol::PacketType::PubComp => {
                        Self::PubComp($pubcomp::decode(raw_packet)?)
                    }
                    $crate::protocol::PacketType::Subscribe => {
                        Self::Subscribe($subscribe::decode(raw_packet)?)
                    }
                    $crate::protocol::PacketType::SubAck => {
                        Self::SubAck($suback::decode(raw_packet)?)
                    }
                    $crate::protocol::PacketType::Unsubscribe => {
                        Self::Unsubscribe($unsubscribe::decode(raw_packet)?)
                    }
                    $crate::protocol::PacketType::UnsubAck => {
                        Self::UnsubAck($unsuback::decode(raw_packet)?)
                    }

                    // 'PingReq', 'PingResp' or 'Disconnect' packets have no payload
                    _ => return Err($crate::Error::MalformedPacket),
                };

                Ok(decoded)
            }

            pub fn encode(&self, buf: &mut bytes::BytesMut) -> Result<(), $crate::Error> {
                match self {
                    Self::Connect(packet) => packet.encode(buf),
                    Self::ConnAck(packet) => packet.encode(buf),
                    Self::Publish(packet) => packet.encode(buf),
                    Self::PubAck(packet) => packet.encode(buf),
                    Self::PubRec(packet) => packet.encode(buf),
                    Self::PubRel(packet) => packet.encode(buf),
                    Self::PubComp(packet) => packet.encode(buf),
                    Self::Subscribe(packet) => packet.encode(buf),
                    Self::SubAck(packet) => packet.encode(buf),
                    Self::Unsubscribe(packet) => packet.encode(buf),
                    Self::UnsubAck(packet) => packet.encode(buf),
                    Self::PingReq(packet) => packet.encode(buf),
                    Self::PingResp(packet) => packet.encode(buf),
                    Self::Disconnect(packet) => packet.encode(buf),
                }
            }
        }
    };
}

macro_rules! id_packet {
    ($packet:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $packet {
            packet_id: u16,
        }

        impl $packet {
            pub fn new(packet_id: u16) -> Self {
                if packet_id == 0 {
                    panic!("Packet id is zero");
                }

                $packet { packet_id }
            }

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

            fn encoded_len(&self) -> usize {
                2 + 2 // Fixed header size + variable header size
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

            fn encoded_len(&self) -> usize {
                // Fixed header size
                2
            }
        }
    };
}

pub(crate) use header_packet_decode_impl;
pub(crate) use header_packet_encode_impl;
pub(crate) use id_packet;
pub(crate) use id_packet_decode_impl;
pub(crate) use id_packet_encode_impl;
pub(crate) use packet;
