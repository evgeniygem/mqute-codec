use crate::protocol::v5::reason::ReasonCode;
use crate::protocol::v5::util::{
    ack, ack_decode_impl, ack_encode_impl, ack_properties, ack_properties_frame_impl,
};
use crate::protocol::{Flags, PacketType, QoS};

fn validate_pubrel_reason_code(code: ReasonCode) -> bool {
    matches!(code.into(), 0 | 146)
}

ack_properties!(PubRelProperties);
ack_properties_frame_impl!(PubRelProperties);
ack!(PubRel, PubRelProperties, validate_pubrel_reason_code);
ack_decode_impl!(
    PubRel,
    PacketType::PubRel,
    Flags::new(QoS::AtLeastOnce),
    validate_pubrel_reason_code
);
ack_encode_impl!(PubRel, PacketType::PubRel, Flags::new(QoS::AtLeastOnce));
