//! # RawPacket and PacketCodec
//!
//! This module provides the `RawPacket` struct, which represents a raw MQTT packet,
//! and the `PacketCodec` struct, which implements encoding and decoding of MQTT packets
//! using the `tokio_util::codec` traits.
//!
//! ## Overview
//!
//! - `RawPacket`: Represents a raw MQTT packet, consisting of a fixed header and a payload.
//! - `PacketCodec`: A codec for encoding and decoding MQTT packets, with support for
//!   size limits on inbound and outbound packets.

use super::{Encode, Encoded};
use crate::protocol::FixedHeader;
use crate::Error;
use bytes::{Buf, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// Represents a raw MQTT packet.
///
/// A raw packet consists of:
/// - A fixed header (`FixedHeader`), which contains metadata about the packet.
/// - A payload (`Bytes`), which contains the variable header and payload data.
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// The fixed header of the packet.
    pub header: FixedHeader,

    /// The variable header and payload of the packet.
    pub payload: Bytes,
}

impl RawPacket {
    /// Creates a new `RawPacket` with the specified fixed header and payload.
    ///
    /// # Panics
    /// Panics if the length of the payload does not match the remaining length specified
    /// in the fixed header.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::codec::{RawPacket};
    /// use mqute_codec::protocol::{FixedHeader, PacketType};
    /// use bytes::Bytes;
    ///
    /// let header = FixedHeader::new(PacketType::Publish, 4);
    /// let payload = Bytes::from_static(&[0x00, 0x01, 0x02, 0x03]);
    /// let packet = RawPacket::new(header, payload);
    /// ```
    pub fn new(header: FixedHeader, payload: Bytes) -> Self {
        if header.remaining_len() != payload.len() {
            panic!("Header and payload mismatch");
        }
        RawPacket { header, payload }
    }
}

/// A codec for encoding and decoding MQTT packets.
///
/// The `PacketCodec` struct implements the `Encoder` and `Decoder` traits from the
/// `tokio_util::codec` module, allowing it to be used with asynchronous I/O frameworks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketCodec {
    /// The maximum allowed size for inbound packets.
    inbound_max_size: Option<usize>,

    /// The maximum allowed size for outbound packets.
    outbound_max_size: Option<usize>,
}

impl PacketCodec {
    /// Creates a new `PacketCodec` with the specified size limits.
    ///
    /// # Arguments
    /// - `inbound_max_size`: The maximum allowed size for inbound packets.
    /// - `outbound_max_size`: The maximum allowed size for outbound packets.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::codec::PacketCodec;
    ///
    /// let codec = PacketCodec::new(Some(1024), Some(1024));
    /// ```
    pub fn new(inbound_max_size: Option<usize>, outbound_max_size: Option<usize>) -> Self {
        PacketCodec {
            inbound_max_size,
            outbound_max_size,
        }
    }

    /// Attempts to decode a raw packet from the provided buffer.
    ///
    /// # Arguments
    /// - `dst`: The buffer containing the raw packet data.
    ///
    /// # Returns
    /// - `Ok(RawPacket)`: If decoding is successful.
    /// - `Err(Error)`: If decoding fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::codec::PacketCodec;
    /// use mqute_codec::protocol::{FixedHeader, PacketType};
    /// use bytes::BytesMut;
    ///
    /// let mut codec = PacketCodec::new(Some(1024), Some(1024));
    /// let mut buffer = BytesMut::from(&[0x30, 0x02, 0x00, 0x01][..]); // Example raw packet
    /// let packet = codec.try_decode(&mut buffer).unwrap();
    /// ```
    pub fn try_decode(&self, dst: &mut BytesMut) -> Result<RawPacket, Error> {
        // Decode the header and check the allowable size
        let header = FixedHeader::decode(dst, self.inbound_max_size)?;

        let mut payload = dst.split_to(header.packet_len()).freeze();

        // Skip the header data
        payload.advance(header.fixed_len());

        Ok(RawPacket::new(header, payload))
    }
}

impl<T> Encoder<T> for PacketCodec
where
    T: Encode,
{
    type Error = Error;

    /// Encodes an item into the provided buffer.
    ///
    /// # Arguments
    /// - `item`: The item to encode.
    /// - `dst`: The buffer to write the encoded data into.
    ///
    /// # Returns
    /// - `Ok(())`: If encoding is successful.
    /// - `Err(Error)`: If encoding fails or the outbound size limit is exceeded.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::codec::{PacketCodec, Encode};
    /// use tokio_util::codec::Encoder;
    /// use bytes::BytesMut;
    /// use mqute_codec::Error;
    ///
    /// struct MyPacket;
    ///
    /// impl Encode for MyPacket {
    ///     fn encode(&self, dst: &mut BytesMut) -> Result<(), Error> {
    ///         dst.extend_from_slice(&[0x30, 0x02, 0x00, 0x01]);
    ///         Ok(())
    ///     }
    ///
    /// fn payload_len(&self) -> usize {
    ///         4
    ///     }
    /// }
    ///
    /// let mut codec = PacketCodec::new(Some(1024), Some(1024));
    /// let mut buffer = BytesMut::new();
    /// let packet = MyPacket {};
    /// codec.encode(packet, &mut buffer).unwrap();
    ///
    /// assert_eq!(buffer.as_ref(), &[0x30, 0x02, 0x00, 0x01]);
    /// ```
    fn encode(&mut self, item: T, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if let Some(max_size) = self.outbound_max_size {
            if item.encoded_len() > max_size {
                return Err(Error::OutgoingPayloadSizeLimitExceeded(item.encoded_len()));
            }
        }

        item.encode(dst)
    }
}

impl Decoder for PacketCodec {
    type Item = RawPacket;
    type Error = Error;

    /// Decodes a raw packet from the provided buffer.
    ///
    /// # Arguments
    /// - `src`: The buffer containing the raw packet data.
    ///
    /// # Returns
    /// - `Ok(Some(RawPacket))`: If decoding is successful.
    /// - `Ok(None)`: If more data is needed to decode the packet.
    /// - `Err(Error)`: If decoding fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::codec::PacketCodec;
    /// use mqute_codec::protocol::PacketType;
    /// use tokio_util::codec::Decoder;
    /// use bytes::BytesMut;
    ///
    /// let mut codec = PacketCodec::new(Some(1024), Some(1024));
    /// let mut buffer = BytesMut::from(&[0x30, 0x02, 0x00, 0x01][..]); // Example raw packet
    /// let packet = codec.decode(&mut buffer).unwrap().unwrap();
    ///
    /// assert_eq!(packet.header.packet_type(), PacketType::Publish);
    /// assert_eq!(packet.payload.len(), 2);
    /// ```
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.try_decode(src) {
            Ok(packet) => Ok(Some(packet)),
            Err(Error::NotEnoughBytes(len)) => {
                // Get more packets to construct the incomplete packet
                src.reserve(len);
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}
