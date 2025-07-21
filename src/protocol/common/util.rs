//! The packet! macro generates an enum and associated methods for handling MQTT packets. It takes
//! identifiers for each MQTT packet type as input and creates a unified Packet enum that can
//! represent any MQTT packet (only V4 and V3).

macro_rules! packet {
    ($packet:ident, $connect:ident, $connack:ident,
     $publish:ident, $puback:ident, $pubrec:ident,
     $pubrel:ident, $pubcomp:ident, $subscribe:ident,
     $suback:ident, $unsubscribe:ident, $unsuback:ident,
     $pingreq:ident, $pingresp:ident, $disconnect:ident) => {
        use $crate::codec::{Decode, Encode};

        /// Represents all possible MQTT v3.x packet types
        ///
        /// This enum serves as the main abstraction for working with MQTT packets,
        /// providing a unified interface for packet handling while maintaining
        /// type safety for each specific packet type.
        pub enum $packet {
            /// Client-initiated connection request. First packet in connection establishment flow
            Connect($connect),

            /// Server connection acknowledgment. Sent in response to CONNECT packet
            ConnAck($connack),

            /// Message publication. Primary message delivery mechanism.
            Publish($publish),

            /// QoS 1 publication acknowledgment. Acknowledges receipt of QoS 1 messages
            PubAck($puback),

            /// QoS 2 publication received (part 1). First packet in QoS 2 protocol flow
            PubRec($pubrec),

            /// QoS 2 publication release (part 2). Second packet in QoS 2 protocol flow
            PubRel($pubrel),

            /// QoS 2 publication complete (part 3). Final packet in QoS 2 protocol flow
            PubComp($pubcomp),

            /// Subscription request. Begins subscription creation/modification
            Subscribe($subscribe),

            /// Subscription acknowledgment. Confirms subscription processing results
            SubAck($suback),

            /// Unsubscription request. Begins subscription termination
            Unsubscribe($unsubscribe),

            /// Unsubscription acknowledgment. Confirms unsubscription processing
            UnsubAck($unsuback),

            /// Keep-alive ping request. Must be responded to with PINGRESP
            PingReq($pingreq),

            /// Keep-alive ping response. Sent in response to PINGREQ to confirm connection is active
            PingResp($pingresp),

            /// Graceful connection termination. Properly closes the MQTT connection
            Disconnect($disconnect),
        }

        impl $packet {
            /// Decodes a raw MQTT packet into the appropriate Packet variant
            ///
            /// This is the primary entry point for packet processing, handling:
            /// - Packet type identification
            /// - Payload validation
            /// - Special cases for empty payload packets
            /// - Delegation to specific packet decoders
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

            /// Encodes the packet into its wire format
            ///
            /// Delegates to the specific packet implementation's encoder while
            /// providing a unified interface for all packet types.
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
