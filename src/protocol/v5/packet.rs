//! # MQTT v5 Packet Enumeration
//!
//! This module provides a unified `Packet` enum that represents all possible MQTT v5 packet types.
//! It serves as the primary interface for decoding and encoding MQTT packets, handling the complete
//! protocol specification including all control packet types.

use crate::Error;
use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::PacketType;
use crate::protocol::v5::{
    Auth, ConnAck, Connect, Disconnect, PingReq, PingResp, PubAck, PubComp, PubRec, PubRel,
    Publish, SubAck, Subscribe, UnsubAck, Unsubscribe,
};

/// Represents all possible MQTT v5 packet types
///
/// This enum serves as the main abstraction for working with MQTT packets,
/// providing a unified interface for packet handling while maintaining
/// type safety for each specific packet type.
///
/// # Example
///
/// ```rust
/// use mqute_codec::protocol::v5::Packet;
/// use mqute_codec::protocol::v5::{Connect, ConnectProperties};
/// use bytes::{Bytes, BytesMut};
///
/// let properties = ConnectProperties {
///     session_expiry_interval: Some(3600),
///     ..Default::default()
/// };
///
/// let connect = Connect::with_properties(
///     "client",
///     None,
///     None,
///     properties.clone(),
///     30,
///     true);
///
/// let mut buf = BytesMut::new();
///
/// let packet = Packet::Connect(connect);
///
/// packet.encode(&mut buf).unwrap()
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// Client-initiated connection request. First packet in connection establishment flow
    Connect(Connect),

    /// Server connection acknowledgment. Sent in response to CONNECT packet
    ConnAck(ConnAck),

    /// Message publication. Primary message delivery mechanism.
    Publish(Publish),

    /// QoS 1 publication acknowledgment. Acknowledges receipt of QoS 1 messages
    PubAck(PubAck),

    /// QoS 2 publication received (part 1). First packet in QoS 2 protocol flow
    PubRec(PubRec),

    /// QoS 2 publication release (part 2). Second packet in QoS 2 protocol flow
    PubRel(PubRel),

    /// QoS 2 publication complete (part 3). Final packet in QoS 2 protocol flow
    PubComp(PubComp),

    /// Subscription request. Begins subscription creation/modification
    Subscribe(Subscribe),

    /// Subscription acknowledgment. Confirms subscription processing results
    SubAck(SubAck),

    /// Unsubscription request. Begins subscription termination
    Unsubscribe(Unsubscribe),

    /// Unsubscription acknowledgment. Confirms unsubscription processing
    UnsubAck(UnsubAck),

    /// Keep-alive ping request. Must be responded to with PINGRESP
    PingReq(PingReq),

    /// Keep-alive ping response. Sent in response to PINGREQ to confirm connection is active
    PingResp(PingResp),

    /// Graceful connection termination. Properly closes the MQTT connection
    Disconnect(Disconnect),

    /// Authentication exchange. Used for extended authentication flows
    Auth(Auth),
}

impl Packet {
    /// Decodes a raw MQTT packet into the appropriate Packet variant
    ///
    /// This is the primary entry point for packet processing, handling:
    /// - Packet type identification
    /// - Payload validation
    /// - Special cases for empty payload packets
    /// - Delegation to specific packet decoders
    pub fn decode(raw_packet: RawPacket) -> Result<Self, Error> {
        let packet_type = raw_packet.header.packet_type();

        // Handle packets that may have empty payloads
        if raw_packet.header.remaining_len() == 0 {
            return match packet_type {
                PacketType::PingReq => Ok(Self::PingReq(PingReq::decode(raw_packet)?)),
                PacketType::PingResp => Ok(Self::PingResp(PingResp::decode(raw_packet)?)),
                PacketType::Disconnect => Ok(Self::Disconnect(Disconnect::decode(raw_packet)?)),
                PacketType::Auth => Ok(Self::Auth(Auth::decode(raw_packet)?)),
                _ => Err(Error::PayloadRequired),
            };
        }

        // Dispatch to appropriate packet decoder
        let decoded = match packet_type {
            PacketType::Connect => Self::Connect(Connect::decode(raw_packet)?),
            PacketType::ConnAck => Self::ConnAck(ConnAck::decode(raw_packet)?),
            PacketType::Publish => Self::Publish(Publish::decode(raw_packet)?),
            PacketType::PubAck => Self::PubAck(PubAck::decode(raw_packet)?),
            PacketType::PubRec => Self::PubRec(PubRec::decode(raw_packet)?),
            PacketType::PubRel => Self::PubRel(PubRel::decode(raw_packet)?),
            PacketType::PubComp => Self::PubComp(PubComp::decode(raw_packet)?),
            PacketType::Subscribe => Self::Subscribe(Subscribe::decode(raw_packet)?),
            PacketType::SubAck => Self::SubAck(SubAck::decode(raw_packet)?),
            PacketType::Unsubscribe => Self::Unsubscribe(Unsubscribe::decode(raw_packet)?),
            PacketType::UnsubAck => Self::UnsubAck(UnsubAck::decode(raw_packet)?),
            PacketType::Disconnect => Self::Disconnect(Disconnect::decode(raw_packet)?),
            PacketType::Auth => Self::Auth(Auth::decode(raw_packet)?),
            // Ping packets should have been handled above
            _ => return Err(Error::MalformedPacket),
        };

        Ok(decoded)
    }

    /// Encodes the packet into its wire format
    ///
    /// Delegates to the specific packet implementation's encoder while
    /// providing a unified interface for all packet types.
    pub fn encode(&self, buf: &mut bytes::BytesMut) -> Result<(), Error> {
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
            Self::Auth(packet) => packet.encode(buf),
        }
    }
}
