//! # Publish Complete Packet V5
//!
//! This module implements the MQTT v5 PubComp packet which is the final packet in
//! the QoS 2 protocol flow, sent by either client or server to confirm receipt of
//! a PubRel packet.

use crate::protocol::v5::reason::ReasonCode;
use crate::protocol::v5::util::{
    ack, ack_decode_impl, ack_encode_impl, ack_properties, ack_properties_frame_impl,
};
use crate::protocol::{Flags, PacketType};

/// Validates that a reason code is appropriate for a `PubComp` packet
///
/// MQTT v5 defines specific allowed reason codes for `PubComp`:
/// - Success (0) - Normal completion of QoS 2 flow
/// - Packet Identifier Not Found (146) - When the packet ID is unknown
fn validate_pubcomp_reason_code(code: ReasonCode) -> bool {
    matches!(code.into(), 0 | 146)
}

// Defines properties specific to `PubComp` packets
ack_properties!(PubCompProperties);

// Implements property frame handling for PubCompProperties
ack_properties_frame_impl!(PubCompProperties);

// Represents an MQTT v5 `PubComp` packet
ack!(PubComp, PubCompProperties, validate_pubcomp_reason_code);

// Implement decoding for `PubComp` packets
ack_decode_impl!(
    PubComp,
    PacketType::PubComp,
    Flags::default(),
    validate_pubcomp_reason_code
);

// Implement encoding for `PubComp` packets
ack_encode_impl!(PubComp, PacketType::PubComp, Flags::default());
