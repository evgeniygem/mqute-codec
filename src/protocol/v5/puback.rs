use crate::protocol::v5::reason::ReasonCode;
use crate::protocol::v5::util::{
    ack, ack_decode_impl, ack_encode_impl, ack_properties, ack_properties_frame_impl,
};
use crate::protocol::{Flags, PacketType};

fn validate_puback_reason_code(code: ReasonCode) -> bool {
    matches!(
        code.into(),
        0 | 16 | 128 | 131 | 135 | 144 | 145 | 151 | 153
    )
}

ack_properties!(PubAckProperties);
ack!(PubAck, PubAckProperties, validate_puback_reason_code);

ack_decode_impl!(
    PubAck,
    PacketType::PubAck,
    Flags::default(),
    validate_puback_reason_code
);
ack_encode_impl!(PubAck, PacketType::PubAck, Flags::default());
ack_properties_frame_impl!(PubAckProperties);
