//! # Publish Acknowledgement Packet V5
//!
//! This module implements the MQTT v5 `PubAck` packet which is sent by the server
//! to acknowledge receipt of a QoS 1 PUBLISH packet from the client, or by the client
//! to acknowledge receipt of a QoS 1 PUBLISH packet from the server.
//!

use crate::protocol::v5::reason::ReasonCode;
use crate::protocol::v5::util::{
    ack, ack_decode_impl, ack_encode_impl, ack_properties, ack_properties_frame_impl,
};
use crate::protocol::{Flags, PacketType, traits};

/// Validates that a reason code is acceptable for a `PubAck` packet.
///
/// MQTT v5 defines specific reason codes that are valid for `PubAck` packets:
/// - Success (0)
/// - No matching subscribers (16)
/// - Unspecified error (128)
/// - Implementation specific error (131)
/// - Not authorized (135)
/// - Topic Name invalid (144)
/// - Packet Identifier in use (145)
/// - Quota exceeded (151)
/// - Payload format invalid (153)
fn validate_puback_reason_code(code: ReasonCode) -> bool {
    matches!(
        code.into(),
        0 | 16 | 128 | 131 | 135 | 144 | 145 | 151 | 153
    )
}

// Defines properties specific to PubAck packets
ack_properties!(PubAckProperties);

// Represents an MQTT v5 `PubAck` packet
ack!(PubAck, PubAckProperties, validate_puback_reason_code);

// Implement decoding for `PubAck` packets
ack_decode_impl!(
    PubAck,
    PacketType::PubAck,
    Flags::default(),
    validate_puback_reason_code
);

// Implement encoding for `PubAck` packets
ack_encode_impl!(PubAck, PacketType::PubAck, Flags::default());

// Implement property frame handling for PubAckProperties
ack_properties_frame_impl!(PubAckProperties);

impl traits::PubAck for PubAck {}
