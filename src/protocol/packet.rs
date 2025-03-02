//! # MQTT Packet Type
//!
//! This module provides an enum to represent the types of MQTT packets and utilities
//! for converting between packet types and their corresponding numeric values.
//!
//! ## Overview
//!
//! The `PacketType` enum represents the types of MQTT packets as defined by the MQTT protocol.
//! Each packet type corresponds to a specific numeric value, which is used in the fixed header
//! of MQTT packets.

use crate::Error;

/// Represents the type of MQTT packet.
///
/// Each packet type corresponds to a specific numeric value, as defined by the MQTT protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Client request to connect to the server.
    Connect = 1,
    /// Connect acknowledgment.
    ConnAck,
    /// Publish message.
    Publish,
    /// Publish acknowledgment.
    PubAck,
    /// Publish received (assured delivery part 1).
    PubRec,
    /// Publish release (assured delivery part 2).
    PubRel,
    /// Publish complete (assured delivery part 3).
    PubComp,
    /// Client subscribe request.
    Subscribe,
    /// Subscribe acknowledgment.
    SubAck,
    /// Unsubscribe request.
    Unsubscribe,
    /// Unsubscribe acknowledgment.
    UnsubAck,
    /// PING request.
    PingReq,
    /// PING response.
    PingResp,
    /// Client is disconnecting.
    Disconnect,
    /// Authentication exchange.
    Auth,
}

impl TryFrom<u8> for PacketType {
    type Error = Error;

    /// Attempts to convert a numeric value into a `PacketType` enum.
    ///
    /// # Arguments
    /// - `value`: The numeric value representing the packet type.
    ///
    /// # Errors
    /// Returns an `Error::InvalidPacketType` if the value is not a valid packet type.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::protocol::PacketType;
    /// use mqute_codec::Error;
    ///
    /// let packet_type = PacketType::try_from(3).unwrap();
    /// assert_eq!(packet_type, PacketType::Publish);
    ///
    /// let result = PacketType::try_from(16);
    /// assert!(result.is_err());
    /// ```
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let packet_type = match value {
            1 => PacketType::Connect,
            2 => PacketType::ConnAck,
            3 => PacketType::Publish,
            4 => PacketType::PubAck,
            5 => PacketType::PubRec,
            6 => PacketType::PubRel,
            7 => PacketType::PubComp,
            8 => PacketType::Subscribe,
            9 => PacketType::SubAck,
            10 => PacketType::Unsubscribe,
            11 => PacketType::UnsubAck,
            12 => PacketType::PingReq,
            13 => PacketType::PingResp,
            14 => PacketType::Disconnect,
            15 => PacketType::Auth,
            _ => return Err(Error::InvalidPacketType(value)),
        };

        Ok(packet_type)
    }
}
