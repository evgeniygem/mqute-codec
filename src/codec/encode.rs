//! # Encoding Traits
//!
//! This module provides the `Encode` and `Encoded` traits, which define a common interface
//! for encoding MQTT packets into a buffer and calculating their encoded length.
//!
//! - `Encode`: A trait for encoding MQTT packets into a buffer.
//! - `Encoded`: A trait for calculating the total encoded length of an MQTT packet,
//!   including the fixed header and payload.

use crate::protocol::util;
use crate::Error;
use bytes::BytesMut;

/// A trait for encoding MQTT packets into a buffer.
///
/// Types that implement this trait can be serialized into a `BytesMut` buffer for
/// transmission over the network.
pub trait Encode {
    /// Encodes the packet into the provided buffer.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mqute_codec::codec::{Encode, Encoded};
    /// use bytes::BytesMut;
    /// use mqute_codec::Error;
    ///
    /// struct Packet {
    ///     payload: Vec<u8>,
    /// }
    ///
    /// impl Encode for Packet {
    ///     fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
    ///         buf.extend_from_slice(&self.payload);
    ///         Ok(())
    ///     }
    ///
    ///     fn payload_len(&self) -> usize {
    ///         self.payload.len()
    ///     }
    /// }
    ///
    /// let packet = Packet { payload: vec![0x30, 0x00] };
    /// let mut buffer = BytesMut::new();
    /// packet.encode(&mut buffer).unwrap();
    /// assert_eq!(buffer.to_vec(), vec![0x30, 0x00]);
    /// ```
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error>;

    /// Returns the length of the payload in bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mqute_codec::codec::{Encode, Encoded};
    /// use bytes::BytesMut;
    /// use mqute_codec::Error;
    ///
    /// struct Packet {
    ///     payload: Vec<u8>,
    /// }
    ///
    /// impl Encode for Packet {
    ///     fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
    ///         buf.extend_from_slice(&self.payload);
    ///         Ok(())
    ///     }
    ///
    ///     fn payload_len(&self) -> usize {
    ///         self.payload.len()
    ///     }
    /// }
    ///
    /// let packet = Packet { payload: vec![0x00, 0x01] };
    /// assert_eq!(packet.payload_len(), 2);
    /// ```
    fn payload_len(&self) -> usize;
}

/// A trait for calculating the total encoded length of an MQTT packet.
///
/// This trait is automatically implemented for all types that implement `Encode`.
///
/// # Examples
///
/// ```rust
/// use mqute_codec::codec::{Encode, Encoded};
/// use bytes::BytesMut;
/// use mqute_codec::Error;
///
/// struct Packet {
///     payload: Vec<u8>,
/// }
///
/// impl Encode for Packet {
///     fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
///         buf.extend_from_slice(&self.payload);
///         Ok(())
///     }
///
///     fn payload_len(&self) -> usize {
///         self.payload.len()
///     }
/// }
///
/// let packet = Packet { payload: vec![0x00, 0x01] };
/// assert_eq!(packet.encoded_len(), 4); // 1 byte for control byte, 1 byte for remaining length, 2 bytes for payload
/// ```
pub trait Encoded: Encode {
    /// Calculates the total encoded length of the packet.
    ///
    /// The total length includes:
    /// - 1 byte for the control byte.
    /// - Variable bytes for the remaining length (encoded as a variable byte integer).
    /// - The length of the payload.
    fn encoded_len(&self) -> usize;
}

impl<T> Encoded for T
where
    T: Encode,
{
    fn encoded_len(&self) -> usize {
        let len = self.payload_len();
        1 + util::len_bytes(len) + len
    }
}
