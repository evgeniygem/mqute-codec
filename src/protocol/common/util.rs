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

pub(crate) use packet;
