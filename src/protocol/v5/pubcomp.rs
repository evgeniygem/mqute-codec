use crate::protocol::v5::reason::ReasonCode;
use crate::protocol::v5::util::{
    ack, ack_decode_impl, ack_encode_impl, ack_properties, ack_properties_frame_impl,
};
use crate::protocol::{Flags, PacketType};

fn validate_pubcomp_reason_code(code: ReasonCode) -> bool {
    matches!(code.into(), 0 | 146)
}

ack_properties!(PubCompProperties);
ack_properties_frame_impl!(PubCompProperties);

ack!(PubComp, PubCompProperties, validate_pubcomp_reason_code);
ack_decode_impl!(
    PubComp,
    PacketType::PubComp,
    Flags::default(),
    validate_pubcomp_reason_code
);
ack_encode_impl!(PubComp, PacketType::PubComp, Flags::default());
