//! # Subscribe Acknowledgment (SUBACK) Packet - MQTT v5
//!
//! This module implements the MQTT v5 `SubAck` packet, which is sent by the server
//! to acknowledge receipt and processing of a SUBSCRIBE packet. The `SubAck` packet
//! contains return codes indicating the QoS level granted for each subscription.

use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::v5::reason::ReasonCode;
use crate::protocol::v5::util::{ack_properties, ack_properties_frame_impl, id_header};
use crate::protocol::{Codes, FixedHeader, PacketType};
use crate::Error;
use bytes::{Buf, Bytes, BytesMut};

// Defines properties specific to `SubAck` packets
ack_properties!(SubAckProperties);

// Implements the PropertyFrame trait for SubAckProperties
ack_properties_frame_impl!(SubAckProperties);

/// Validates reason codes for `SubAck` packets
///
/// MQTT v5 specifies the following valid reason codes for `SubAck`:
/// - 0x00 (Granted QoS 0)
/// - 0x01 (Granted QoS 1)
/// - 0x02 (Granted QoS 2)
/// - 0x80 (Unspecified error)
/// - 0x83 (Implementation specific error)
/// - 0x87 (Not authorized)
/// - 0x8F (Topic Filter invalid)
/// - 0x91 (Packet Identifier in use)
/// - 0x97 (Quota exceeded)
/// - 0x9E (Shared Subscriptions not supported)
/// - 0xA1 (Subscription Identifiers not supported)
/// - 0xA2 (Wildcard Subscriptions not supported)
fn validate_suback_reason_code(code: ReasonCode) -> bool {
    matches!(
        code.into(),
        0 | 1 | 2 | 128 | 131 | 135 | 143 | 145 | 151 | 158 | 161 | 162
    )
}

// Internal header structure for `SubAck` packets
id_header!(SubAckHeader, SubAckProperties);

/// Represents an MQTT v5 `SubAck` packet
///
/// The `SubAck` packet is sent by the server to acknowledge receipt and processing
/// of a SUBSCRIBE packet. It contains:
/// - Packet Identifier matching the SUBSCRIBE packet
/// - List of return codes indicating granted QoS levels or errors
/// - Optional properties (v5 only)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubAck {
    header: SubAckHeader,
    codes: Codes<ReasonCode>,
}

impl SubAck {
    /// Creates a new `SubAck` packet
    ///
    /// # Panics
    /// - If no reason codes are provided
    /// - If any reason code is invalid for `SubAck`
    ///
    /// # Example
    /// ```rust
    /// use mqute_codec::protocol::v5::{SubAck, ReasonCode};
    ///
    /// // Successful subscription with different QoS levels
    /// let suback = SubAck::new(
    ///     1234,
    ///     None,
    ///     vec![
    ///         ReasonCode::GrantedQos0,
    ///         ReasonCode::GrantedQos2,
    ///         ReasonCode::GrantedQos1
    ///     ],
    /// );
    ///
    /// // Subscription with errors
    /// let suback_err = SubAck::new(
    ///     5678,
    ///     None,
    ///     vec![
    ///         ReasonCode::GrantedQos1,
    ///         ReasonCode::NotAuthorized,
    ///         ReasonCode::TopicFilterInvalid
    ///     ],
    /// );
    /// ```
    pub fn new<T>(packet_id: u16, properties: Option<SubAckProperties>, codes: T) -> Self
    where
        T: IntoIterator<Item = ReasonCode>,
    {
        let codes: Vec<ReasonCode> = codes.into_iter().collect();

        if codes.is_empty() {
            panic!("At least one reason code is required");
        }

        if !codes.iter().all(|&code| validate_suback_reason_code(code)) {
            panic!("Invalid reason code");
        }

        let header = SubAckHeader::new(packet_id, properties);

        SubAck {
            header,
            codes: codes.into(),
        }
    }

    /// Returns the packet identifier
    pub fn packet_id(&self) -> u16 {
        self.header.packet_id
    }

    /// Returns the list of reason codes
    pub fn code(&self) -> Codes<ReasonCode> {
        self.codes.clone()
    }

    /// Returns a copy of the properties (if any)
    pub fn properties(&self) -> Option<SubAckProperties> {
        self.header.properties.clone()
    }
}

impl Encode for SubAck {
    /// Encodes the `SubAck` packet into a byte buffer
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::SubAck, self.payload_len());
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

impl Decode for SubAck {
    /// Decodes a `SubAck` packet from raw bytes
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::SubAck || !packet.header.flags().is_default()
        {
            return Err(Error::MalformedPacket);
        }

        let header = SubAckHeader::decode(&mut packet.payload)?;
        let mut codes: Vec<ReasonCode> = Codes::decode(&mut packet.payload)?.into();

        // Convert legacy Success (0x00) to GrantedQos0 for consistency
        for code in codes.iter_mut() {
            if !validate_suback_reason_code(*code) {
                return Err(Error::InvalidReasonCode((*code).into()));
            }
            if (*code) == ReasonCode::Success {
                *code = ReasonCode::GrantedQos0;
            }
        }

        Ok(SubAck {
            header,
            codes: codes.into(),
        })
    }
}
