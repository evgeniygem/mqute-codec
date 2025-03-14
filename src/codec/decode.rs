//! # Decode Trait
//!
//! This module defines the `Decode` trait, which provides a common interface for decoding
//! MQTT packets from their raw representation (`RawPacket`).
//!
//! The `Decode` trait is implemented by types that can be decoded from a raw MQTT packet.

use super::RawPacket;
use crate::Error;

/// A trait for decoding MQTT packets from their raw representation.
///
/// Types that implement this trait can be decoded from a `RawPacket`. This is useful for
/// deserializing MQTT packets received over the network.
pub trait Decode: Sized {
    /// Decodes a raw MQTT packet into the implementing type.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::protocol::{FixedHeader, PacketType};
    /// use mqute_codec::codec::{Decode, RawPacket};
    /// use mqute_codec::Error;
    /// use bytes::Bytes;
    ///
    ///
    /// struct Packet {
    ///     header: FixedHeader,
    ///     payload: Vec<u8>,
    /// }
    ///
    /// impl Decode for Packet {
    ///     fn decode(packet: RawPacket) -> Result<Self, Error> {
    ///         let header = packet.header;
    ///         let payload = packet.payload.to_vec();
    ///         Ok(Packet { header, payload })
    ///     }
    /// }
    ///
    /// let header = FixedHeader::new(PacketType::Connect, 2);
    /// let raw_packet = RawPacket::new(header.clone(), Bytes::copy_from_slice(&[0x00, 0x01])); // Example raw packet
    /// let packet = Packet::decode(raw_packet).unwrap();
    /// assert_eq!(packet.header, header);
    /// assert_eq!(packet.payload, vec![0x00, 0x01]);
    /// ```
    fn decode(packet: RawPacket) -> Result<Self, Error>;
}
