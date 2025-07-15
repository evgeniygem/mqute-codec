//! # Publish Received (PUBREC) Packet - MQTT v5
//!
//! This module implements the MQTT v5 `PubRec` packet, which is the second packet in the
//! Quality of Service 2 (QoS 2) message delivery flow. The `PubRec` packet is sent by the
//! receiver to acknowledge receipt of a QoS 2 PUBLISH packet.

use crate::protocol::v5::reason::ReasonCode;
use crate::protocol::v5::util::{
    ack, ack_decode_impl, ack_encode_impl, ack_properties, ack_properties_frame_impl,
};
use crate::protocol::{Flags, PacketType};

/// Validates reason codes for `PubRec` packets
///
/// MQTT v5 specifies the following valid reason codes for `PubRec`:
/// - 0x00 (Success) - Packet accepted and stored
/// - 0x10 (No matching subscribers) - No subscribers for the topic
/// - 0x80 (Unspecified error) - Unspecified error condition
/// - 0x83 (Implementation specific error) - Implementation-specific error
/// - 0x87 (Not authorized) - Client not authorized
/// - 0x90 (Topic Name invalid) - Malformed topic name
/// - 0x91 (Packet Identifier in use) - Duplicate packet ID
/// - 0x97 (Quota exceeded) - Message quota exceeded
/// - 0x99 (Payload format invalid) - Invalid payload format
fn validate_pubrec_reason_code(code: ReasonCode) -> bool {
    matches!(
        code.into(),
        0 | 16 | 128 | 131 | 135 | 144 | 145 | 151 | 153
    )
}

// Defines properties specific to `PubRec` packets
ack_properties!(PubRecProperties);

// Implements the PropertyFrame trait for PubRecProperties
ack_properties_frame_impl!(PubRecProperties);

// Represents an MQTT v5 `PubRec` packet
ack!(PubRec, PubRecProperties, validate_pubrec_reason_code);

// Implements packet decoding for `PubRec`
ack_decode_impl!(
    PubRec,
    PacketType::PubRec,
    Flags::default(),
    validate_pubrec_reason_code
);

// Implements packet encoding for `PubRec`
ack_encode_impl!(PubRec, PacketType::PubRec, Flags::default());
