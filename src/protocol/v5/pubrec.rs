use crate::protocol::v5::reason::ReasonCode;
use crate::protocol::v5::util::{
    ack, ack_decode_impl, ack_encode_impl, ack_properties, ack_properties_frame_impl,
};
use crate::protocol::{Flags, PacketType};

fn validate_pubrec_reason_code(code: ReasonCode) -> bool {
    matches!(
        code.into(),
        0 | 16 | 128 | 131 | 135 | 144 | 145 | 151 | 153
    )
}

ack_properties!(PubRecProperties);
ack_properties_frame_impl!(PubRecProperties);

ack!(PubRec, PubRecProperties, validate_pubrec_reason_code);
ack_decode_impl!(
    PubRec,
    PacketType::PubRec,
    Flags::default(),
    validate_pubrec_reason_code
);
ack_encode_impl!(PubRec, PacketType::PubRec, Flags::default());
