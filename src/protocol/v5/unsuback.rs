//! # Unsubscribe Acknowledgment (UnsubAck) Packet - MQTT v5
//!
//! This module implements the MQTT v5 `UnsubAck` packet, which is sent by the server
//! to acknowledge receipt and processing of an UNSUBSCRIBE packet. The `UnsubAck` packet
//! contains return codes indicating the result of each unsubscription request.

use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::v5::reason::ReasonCode;
use crate::protocol::v5::util::{ack_properties, ack_properties_frame_impl, id_header};
use crate::protocol::{Codes, FixedHeader, PacketType};
use crate::Error;
use bytes::{Buf, Bytes, BytesMut};

// Defines properties specific to `UnsubAck` packets
ack_properties!(UnsubAckProperties);

// Implements the PropertyFrame trait for UnsubAckProperties
ack_properties_frame_impl!(UnsubAckProperties);

/// Validates reason codes for `UnsubAck` packets
///
/// MQTT v5 specifies the following valid reason codes for `UnsubAck`:
/// - 0x00 (Success) - Unsubscription successful
/// - 0x11 (No subscription existed) - No matching subscription found
/// - 0x80 (Unspecified error) - Unspecified error condition
/// - 0x83 (Implementation specific error) - Implementation-specific error
/// - 0x87 (Not authorized) - Client not authorized
/// - 0x8F (Topic Filter invalid) - Invalid topic filter format
/// - 0x91 (Packet Identifier in use) - Duplicate packet ID
fn validate_unsuback_reason_code(code: ReasonCode) -> bool {
    matches!(code.into(), 0 | 17 | 128 | 131 | 135 | 143 | 145)
}

// Internal header structure for `UnsubAck` packets
id_header!(UnsubAckHeader, UnsubAckProperties);

/// Represents an MQTT v5 `UnsubAck` packet
///
/// The `UnsubAck` packet is sent by the server to acknowledge receipt and processing
/// of an UNSUBSCRIBE packet. It contains:
/// - Packet Identifier matching the UNSUBSCRIBE packet
/// - List of return codes indicating unsubscription results
/// - Optional properties (v5 only)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsubAck {
    header: UnsubAckHeader,
    codes: Codes<ReasonCode>,
}

impl UnsubAck {
    /// Creates a new `UnsubAck` packet
    ///
    /// # Panics
    /// - If no reason codes are provided
    /// - If any reason code is invalid for `UnsubAck`
    ///
    /// # Example
    ///
    /// ```rust
    /// use mqute_codec::protocol::v5::{UnsubAck, ReasonCode};
    ///
    /// // Successful unsubscription
    /// let unsuback = UnsubAck::new(
    ///     1234,
    ///     None,
    ///     vec![ReasonCode::Success, ReasonCode::Success]
    /// );
    ///
    /// // Mixed results unsubscription
    /// let unsuback_mixed = UnsubAck::new(
    ///     5678,
    ///     None,
    ///     vec![
    ///         ReasonCode::Success,
    ///         ReasonCode::NoSubscriptionExisted
    ///     ]
    /// );
    /// ```
    pub fn new<T>(packet_id: u16, properties: Option<UnsubAckProperties>, codes: T) -> Self
    where
        T: IntoIterator<Item = ReasonCode>,
    {
        let codes: Vec<ReasonCode> = codes.into_iter().collect();

        if codes.is_empty() {
            panic!("At least one reason code is required");
        }

        if !codes
            .iter()
            .all(|&code| validate_unsuback_reason_code(code))
        {
            panic!("Invalid reason code");
        }

        let header = UnsubAckHeader::new(packet_id, properties);

        UnsubAck {
            header,
            codes: codes.into(),
        }
    }

    /// Returns the packet identifier
    ///
    /// # Example
    ///
    /// ```rust
    /// use mqute_codec::protocol::v5::{UnsubAck, ReasonCode};
    ///
    /// // Successful unsubscription
    /// let unsuback = UnsubAck::new(
    ///     1234,
    ///     None,
    ///     vec![ReasonCode::Success, ReasonCode::Success]
    /// );
    /// assert_eq!(unsuback.packet_id(), 1234u16);
    /// ```
    pub fn packet_id(&self) -> u16 {
        self.header.packet_id
    }

    /// Returns the list of reason codes
    ///
    /// # Example
    ///
    /// ```rust
    /// use mqute_codec::protocol::Codes;
    /// use mqute_codec::protocol::v5::{UnsubAck, ReasonCode};
    ///
    /// // Successful unsubscription
    /// let unsuback = UnsubAck::new(
    ///     1234,
    ///     None,
    ///     vec![ReasonCode::Success, ReasonCode::Success]
    /// );
    ///
    /// let codes = Codes::new(vec![ReasonCode::Success, ReasonCode::Success]);
    /// assert_eq!(unsuback.codes(), codes);
    /// ```
    pub fn codes(&self) -> Codes<ReasonCode> {
        self.codes.clone()
    }

    /// Returns a copy of the properties (if any)
    ///
    /// # Example
    ///
    /// ```rust
    /// use mqute_codec::protocol::v5::{UnsubAck, ReasonCode, UnsubAckProperties};
    ///
    /// let properties = UnsubAckProperties {
    ///     reason_string: None,
    ///     user_properties: vec![("key".to_string(), "value".to_string())]
    /// };
    ///
    /// // Successful unsubscription
    /// let unsuback = UnsubAck::new(
    ///     1234,
    ///     Some(properties.clone()),
    ///     vec![ReasonCode::Success, ReasonCode::Success]
    /// );
    ///
    /// assert_eq!(unsuback.properties(), Some(properties));
    /// ```
    pub fn properties(&self) -> Option<UnsubAckProperties> {
        self.header.properties.clone()
    }
}

impl Encode for UnsubAck {
    /// Encodes the `UnsubAck` packet into a byte buffer
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::UnsubAck, self.payload_len());
        header.encode(buf)?;

        self.header.encode(buf)?;
        self.codes.encode(buf);
        Ok(())
    }

    /// Calculates the total packet length
    fn payload_len(&self) -> usize {
        self.header.encoded_len() + self.codes.len()
    }
}

impl Decode for UnsubAck {
    /// Decodes an `UnsubAck` packet from raw bytes
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::UnsubAck
            || !packet.header.flags().is_default()
        {
            return Err(Error::MalformedPacket);
        }

        let header = UnsubAckHeader::decode(&mut packet.payload)?;
        let codes = Codes::decode(&mut packet.payload)?;

        let codes: Vec<ReasonCode> = codes.into();

        if !codes
            .iter()
            .all(|&code| validate_unsuback_reason_code(code))
        {
            return Err(Error::MalformedPacket);
        }

        Ok(UnsubAck {
            header,
            codes: codes.into(),
        })
    }
}
