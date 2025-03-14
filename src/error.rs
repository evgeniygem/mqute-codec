//! # Error Handling
//!
//! This module defines the `Error` enum, which represents various errors that can occur
//! when working with the MQTT protocol. The enum is derived using the `thiserror` crate,
//! which provides convenient error handling and formatting.

use std::io;

/// Represents errors that can occur when working with the MQTT protocol.
///
/// Each variant includes a descriptive error message and, where applicable,
/// additional context (e.g., invalid values or sizes).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Indicates an invalid connect return code.
    #[error("Invalid connect return code: {0}")]
    InvalidConnectReturnCode(u8),

    /// Indicates an invalid packet type.
    #[error("Invalid packet type: {0}")]
    InvalidPacketType(u8),

    /// Indicates an invalid reason code.
    #[error("Invalid reason code: {0}")]
    InvalidReasonCode(u8),

    /// Indicates an invalid protocol name.
    #[error("Invalid protocol name: {0}")]
    InvalidProtocolName(String),

    /// Indicates an invalid protocol level.
    #[error("Invalid protocol level: {0}")]
    InvalidProtocolLevel(u8),

    /// Indicates an invalid property.
    #[error("Invalid property: {0}")]
    InvalidProperty(u8),

    /// Indicates invalid UTF-8 data.
    #[error("Invalid UTF-8")]
    InvalidUtf8,

    /// Indicates an invalid QoS level.
    #[error("Invalid QoS: {0}")]
    InvalidQos(u8),

    /// Indicates invalid retain handling.
    #[error("Invalid retain handling: {0}")]
    InvalidRetainHandling(u8),

    /// Wraps an I/O error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Indicates a malformed variable byte integer.
    #[error("Malformed variable byte integer")]
    MalformedVariableByteInteger,

    /// Indicates a malformed packet.
    #[error("Malformed packet")]
    MalformedPacket,

    /// Indicates that the payload must contain at least one return code.
    #[error("The payload of packet must contain at least one return code")]
    NoCodes,

    /// Indicates that there are not enough bytes to frame the packet.
    #[error("At least there are not enough {0} bytes to frame the packet")]
    NotEnoughBytes(usize),

    /// Indicates that the payload must contain at least one topic filter.
    #[error("The payload of packet must contain at least one topic filter")]
    NoTopic,

    /// Indicates that the outgoing payload size limit has been exceeded.
    #[error("Outgoing payload size limit exceeded: {0}")]
    OutgoingPayloadSizeLimitExceeded(usize),

    /// Indicates an out-of-bounds access.
    #[error("Out of bounds")]
    OutOfBounds,

    /// Indicates that the payload is too large.
    #[error("Payload too large")]
    PayloadTooLarge,

    /// Indicates that a payload is required but missing.
    #[error("Payload required")]
    PayloadRequired,

    /// Indicates that the payload size limit has been exceeded.
    #[error("Payload size limit exceeded: {0}")]
    PayloadSizeLimitExceeded(usize),

    /// Indicates a protocol error.
    #[error("Protocol error")]
    ProtocolError,

    /// Indicates a protocol mismatch.
    #[error("Protocol mismatch")]
    ProtocolMismatch,

    /// Indicates that the protocol is not supported.
    #[error("Protocol not supported")]
    ProtocolNotSupported,

    /// Indicates a property mismatch.
    #[error("Property mismatch")]
    PropertyMismatch,

    /// Indicates that a string is too long.
    #[error("String too long")]
    StringTooLong,
}
