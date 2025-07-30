//! # MQTT Protocol - Fixed Header and Flags
//!
//! This module provides structures and utilities for handling the fixed header and flags
//! in the MQTT protocol.
//!
//! The MQTT protocol uses a fixed header to describe the type of packet and its properties.
//! The `FixedHeader` struct represents this header, while the `Flags` struct encapsulates
//! the control flags (DUP, QoS, and RETAIN) associated with the packet.

use crate::codec;
use crate::protocol::util;
use crate::protocol::{PacketType, QoS};
use crate::Error;
use bytes::{Buf, BufMut, BytesMut};
use std::cmp::PartialEq;

/// Represents the control flags in an MQTT packet.
///
/// # Examples
///
/// ```rust
/// use mqute_codec::protocol::QoS;
/// use mqute_codec::protocol::Flags;
///
/// // Create default flags
/// let default_flags = Flags::default();
/// assert_eq!(default_flags.dup, false);
/// assert_eq!(default_flags.qos, QoS::AtMostOnce);
/// assert_eq!(default_flags.retain, false);
///
/// // Create custom flags
/// let custom_flags = Flags::new(QoS::AtLeastOnce);
/// assert_eq!(custom_flags.qos, QoS::AtLeastOnce);
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Flags {
    /// Indicates if the packet is a duplicate.
    pub dup: bool,

    /// The Quality of Service level (0, 1, or 2).
    pub qos: QoS,

    /// Indicates if the message should be retained by the broker.
    pub retain: bool,
}

impl Default for Flags {
    /// Creates default `Flags` with:
    /// - `dup`: `false`
    /// - `qos`: `QoS::AtMostOnce`
    /// - `retain`: `false`
    fn default() -> Self {
        Flags {
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
        }
    }
}

impl Flags {
    /// Creates new `Flags` with the specified QoS level.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mqute_codec::protocol::QoS;
    /// use mqute_codec::protocol::Flags;
    ///
    /// let flags = Flags::new(QoS::ExactlyOnce);
    /// assert_eq!(flags.qos, QoS::ExactlyOnce);
    /// ```
    pub fn new(qos: QoS) -> Self {
        Flags {
            dup: false,
            qos,
            retain: false,
        }
    }

    /// Checks if the flags are set to their default values.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mqute_codec::protocol::Flags;
    ///
    /// let flags = Flags::default();
    /// assert!(flags.is_default());
    /// ```
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// Represents the fixed header of an MQTT packet.
///
/// # Examples
///
/// ```
/// use mqute_codec::protocol::{FixedHeader, PacketType};
///
/// // Create a fixed header for a CONNECT packet
/// let header = FixedHeader::new(PacketType::Connect, 10);
/// assert_eq!(header.packet_type(), PacketType::Connect);
/// assert_eq!(header.remaining_len(), 10);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedHeader {
    /// The first byte of the packet, encoding the packet type and flags.
    control_byte: u8,

    /// The length of the remaining payload.
    remaining_len: usize,
}

impl FixedHeader {
    /// Creates a new `FixedHeader` with the specified packet type and remaining length.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::protocol::{FixedHeader, PacketType};
    ///
    /// let header = FixedHeader::new(PacketType::Publish, 20);
    /// assert_eq!(header.packet_type(), PacketType::Publish);
    /// ```
    pub fn new(packet: PacketType, remaining_len: usize) -> Self {
        let control_byte = build_control_byte(packet, Flags::default());

        FixedHeader {
            control_byte,
            remaining_len,
        }
    }

    /// Attempts to create a `FixedHeader` from a control byte and remaining length.
    ///
    /// # Errors
    /// Returns an error if the packet type is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::protocol::{FixedHeader, PacketType};
    /// use mqute_codec::Error;
    ///
    /// let header = FixedHeader::try_from(0x30, 10).unwrap();
    /// assert_eq!(header.packet_type(), PacketType::Publish);
    /// ```
    pub fn try_from(control_byte: u8, remaining_len: usize) -> Result<Self, Error> {
        let _: PacketType = fetch_packet_type(control_byte).try_into()?;

        Ok(FixedHeader {
            control_byte,
            remaining_len,
        })
    }

    /// Creates a `FixedHeader` with custom flags.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::protocol::{FixedHeader, PacketType, Flags};
    /// use mqute_codec::protocol::QoS;
    ///
    /// let flags = Flags::new(QoS::AtLeastOnce);
    /// let header = FixedHeader::with_flags(PacketType::Publish, flags, 15);
    /// assert_eq!(header.flags().qos, QoS::AtLeastOnce);
    /// ```
    pub fn with_flags(packet_type: PacketType, flags: Flags, remaining_len: usize) -> Self {
        let control_byte = build_control_byte(packet_type, flags);
        FixedHeader {
            control_byte,
            remaining_len,
        }
    }

    /// Returns the packet type encoded in the control byte.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::protocol::{FixedHeader, PacketType};
    ///
    /// let header = FixedHeader::new(PacketType::Subscribe, 5);
    /// assert_eq!(header.packet_type(), PacketType::Subscribe);
    /// ```
    pub fn packet_type(&self) -> PacketType {
        fetch_packet_type(self.control_byte).try_into().unwrap()
    }

    /// Extracts and returns the flags from the control byte.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::protocol::{FixedHeader, PacketType, Flags};
    /// use mqute_codec::protocol::QoS;
    ///
    /// let header = FixedHeader::new(PacketType::Publish, 10);
    /// let flags = header.flags();
    /// assert_eq!(flags.qos, QoS::AtMostOnce);
    /// ```
    pub fn flags(&self) -> Flags {
        let flags = self.control_byte & 0x0F;
        let dup: bool = (flags & 0x08) != 0;
        let qos = ((flags >> 1) & 0x03).try_into().unwrap();
        let retain = flags & 0x01 != 0;

        Flags { dup, qos, retain }
    }

    /// Returns the remaining length of the payload.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::protocol::{FixedHeader, PacketType};
    ///
    /// let header = FixedHeader::new(PacketType::Publish, 25);
    /// assert_eq!(header.remaining_len(), 25);
    /// ```
    pub fn remaining_len(&self) -> usize {
        self.remaining_len
    }

    /// Returns the length of the fixed header in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::protocol::{FixedHeader, PacketType};
    ///
    /// let header = FixedHeader::new(PacketType::Publish, 10);
    /// assert_eq!(header.fixed_len(), 2); // 1 byte for control byte, 1 byte for remaining length
    /// ```
    pub fn fixed_len(&self) -> usize {
        util::len_bytes(self.remaining_len) + 1
    }

    /// Returns the total length of the packet (fixed header + payload).
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::protocol::{FixedHeader, PacketType};
    ///
    /// let header = FixedHeader::new(PacketType::Publish, 10);
    /// assert_eq!(header.packet_len(), 12); // 2 bytes for fixed header, 10 bytes for payload
    /// ```
    pub fn packet_len(&self) -> usize {
        self.remaining_len + self.fixed_len()
    }

    /// Encodes the fixed header into a buffer.
    ///
    /// # Errors
    /// Returns an error if encoding fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::protocol::{FixedHeader, PacketType};
    /// use bytes::BytesMut;
    ///
    /// let mut buf = BytesMut::new();
    /// let header = FixedHeader::new(PacketType::Publish, 10);
    /// header.encode(&mut buf).unwrap();
    /// ```
    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        buf.put_u8(self.control_byte);
        codec::util::encode_variable_integer(buf, self.remaining_len as u32)
    }

    /// Decodes a fixed header from a buffer.
    ///
    /// # Errors
    /// Returns an error if decoding fails or the payload size exceeds the limit.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::protocol::{FixedHeader, PacketType};
    /// use bytes::BytesMut;
    ///
    /// let mut buf = BytesMut::from(&[0x30, 0x04,
    ///                                0x00, 0x00,
    ///                                0x00, 0x00][..]); // Publish packet with remaining length 4
    /// let header = FixedHeader::decode(&buf, None).unwrap();
    /// assert_eq!(header.packet_type(), PacketType::Publish);
    /// assert_eq!(header.remaining_len(), 4);
    /// ```
    pub fn decode(buf: &[u8], inbound_max_size: Option<usize>) -> Result<Self, Error> {
        let buf_len = buf.len();
        if buf_len < 2 {
            return Err(Error::NotEnoughBytes(2 - buf_len));
        }

        let mut buf = buf;
        let control_byte = buf.get_u8();
        let remaining_len = codec::util::decode_variable_integer(buf)? as usize;

        let header = FixedHeader::try_from(control_byte, remaining_len)?;

        if let Some(max_size) = inbound_max_size {
            if header.remaining_len > max_size {
                return Err(Error::PayloadSizeLimitExceeded(header.remaining_len));
            }
        }

        let packet_len = header.packet_len();
        if buf_len < packet_len {
            return Err(Error::NotEnoughBytes(packet_len - buf_len));
        }

        Ok(header)
    }
}

/// Extracts the packet type from the control byte.
#[inline]
fn fetch_packet_type(control_byte: u8) -> u8 {
    control_byte >> 4
}

/// Builds the control byte from the packet type and flags.
const fn build_control_byte(packet_type: PacketType, flags: Flags) -> u8 {
    let byte = (packet_type as u8) << 4;
    let flags = (flags.dup as u8) << 3 | (flags.qos as u8) << 1 | (flags.retain as u8);
    byte | flags
}
