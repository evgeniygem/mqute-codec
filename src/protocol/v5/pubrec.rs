//! # Publish Received (PubRec) Packet - MQTT v5
//!
//! This module implements the MQTT v5 `PubRec` packet, which is the second packet in the
//! Quality of Service 2 (QoS 2) message delivery flow. The `PubRec` packet is sent by the
//! receiver to acknowledge receipt of a QoS 2 PUBLISH packet.

use crate::protocol::v5::reason::ReasonCode;
use crate::protocol::v5::util::{
    ack, ack_decode_impl, ack_encode_impl, ack_properties, ack_properties_frame_impl,
};
use crate::protocol::{Flags, PacketType, traits};

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

impl traits::PubRec for PubRec {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PacketCodec;
    use crate::codec::{Decode, Encode};
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    #[test]
    fn pubrec_decode() {
        let mut codec = PacketCodec::new(None, None);

        let data = &[
            (PacketType::PubRec as u8) << 4, // Packet type
            0x04,                            // Remaining len
            0x12,                            // Packet ID
            0x34,                            //
            0x00,                            // Reason code
            0x00,                            // Property len
        ];

        let mut stream = BytesMut::new();

        stream.extend_from_slice(&data[..]);

        let raw_packet = codec.decode(&mut stream).unwrap().unwrap();
        let packet = PubRec::decode(raw_packet).unwrap();

        assert_eq!(packet, PubRec::new(0x1234, ReasonCode::Success, None));
    }

    #[test]
    fn pubrec_encode() {
        let packet = PubRec::new(0x1234, ReasonCode::Success, None);

        let mut stream = BytesMut::new();
        packet.encode(&mut stream).unwrap();
        assert_eq!(
            stream,
            vec![
                (PacketType::PubRec as u8) << 4, // Packet type
                0x02,                            // Remaining len
                0x12,                            // Packet ID
                0x34,                            //
            ]
        );
    }
}
