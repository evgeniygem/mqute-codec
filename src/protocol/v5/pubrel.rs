//! # Publish Release (PubRel) Packet - MQTT v5
//!
//! This module implements the MQTT v5 `PubRel` packet, which is the third packet in the
//! Quality of Service 2 (QoS 2) message delivery flow. The `PubRel` packet is sent by the
//! publisher in response to a `PubRec` to indicate it is releasing the stored message.

use crate::protocol::v5::reason::ReasonCode;
use crate::protocol::v5::util::{
    ack, ack_decode_impl, ack_encode_impl, ack_properties, ack_properties_frame_impl,
};
use crate::protocol::{Flags, PacketType, QoS};

/// Validates reason codes for `PubRel` packets
///
/// MQTT v5 specifies only two valid reason codes for `PubRel`:
/// - 0x00 (Success) - Packet released normally
/// - 0x92 (Packet Identifier Not Found) - When the Packet ID is unknown
fn validate_pubrel_reason_code(code: ReasonCode) -> bool {
    matches!(code.into(), 0 | 146)
}

// Defines properties specific to `PubRel` packets
ack_properties!(PubRelProperties);

// Implements the PropertyFrame trait for PubRelProperties
ack_properties_frame_impl!(PubRelProperties);

// Represents an MQTT v5 `PubRel` packet
ack!(PubRel, PubRelProperties, validate_pubrel_reason_code);

// Implements packet decoding for `PubRel`
ack_decode_impl!(
    PubRel,
    PacketType::PubRel,
    Flags::new(QoS::AtLeastOnce),
    validate_pubrel_reason_code
);

// Implements packet encoding for `PubRel`
ack_encode_impl!(PubRel, PacketType::PubRel, Flags::new(QoS::AtLeastOnce));
