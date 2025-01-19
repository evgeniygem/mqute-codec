/// Error during serialization and deserialization
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid connect return code: {0}")]
    InvalidConnectReturnCode(u8),

    #[error("Invalid packet type: {0}")]
    InvalidPacketType(u8),

    #[error("Invalid reason code: {0}")]
    InvalidReasonCode(u8),

    #[error("Invalid protocol name: {0}")]
    InvalidProtocolName(String),

    #[error("Invalid protocol level: {0}")]
    InvalidProtocolLevel(u8),

    #[error("Invalid UTF-8")]
    InvalidUtf8,

    #[error("Invalid QoS: {0}")]
    InvalidQos(u8),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Malformed remaining length")]
    MalformedRemainingLength,

    #[error("Malformed packet")]
    MalformedPacket,

    #[error("The payload of a Subscribe packet must contain at least one topic filter / QoS pair")]
    NoSubscription,

    #[error("At least there are not enough {0} bytes to frame the packet")]
    NotEnoughBytes(usize),

    #[error("Outgoing payload size limit exceeded: {0}")]
    OutgoingPayloadSizeLimitExceeded(usize),

    #[error("Out of bounds")]
    OutOfBounds,

    #[error("Payload too large")]
    PayloadTooLarge,

    #[error("Payload required")]
    PayloadRequired,

    #[error("Payload size limit exceeded: {0}")]
    PayloadSizeLimitExceeded(usize),

    #[error("String too long")]
    StringTooLong,
}