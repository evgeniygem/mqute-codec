//! # MQTT Error Handling
//!
//! This module defines the `Error` enum, which represents various errors that can occur
//! when working with the MQTT protocol. The enum is derived using the `thiserror` crate,
//! which provides convenient error handling and formatting.

use std::io;

/// Represents errors that can occur when working with the MQTT protocol.
///
/// Each variant includes a descriptive error message and, where applicable,
/// additional context (e.g., invalid values or sizes). This enum implements
/// the standard `Error` trait and can be easily converted from other error types.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Indicates an invalid connect return code received from the broker.
    #[error("Invalid connect return code: {0}")]
    InvalidConnectReturnCode(u8),

    /// Indicates an invalid packet type encountered during parsing.
    #[error("Invalid packet type: {0}")]
    InvalidPacketType(u8),

    /// Indicates an unsupported or invalid protocol level.
    #[error("Invalid protocol level: {0}")]
    InvalidProtocolLevel(u8),

    /// Indicates an invalid or unrecognized protocol name.
    #[error("Invalid protocol name: {0}")]
    InvalidProtocolName(String),

    /// Indicates an invalid property identifier in MQTT properties.
    #[error("Invalid property: {0}")]
    InvalidProperty(u8),

    /// Indicates an invalid Quality of Service level.
    #[error("Invalid QoS: {0} (must be 0, 1, or 2)")]
    InvalidQos(u8),

    /// Indicates an invalid reason code in MQTT response packets.
    #[error("Invalid reason code: {0}")]
    InvalidReasonCode(u8),

    /// Indicates invalid retain handling configuration.
    #[error("Invalid retain handling: {0}")]
    InvalidRetainHandling(u8),

    /// Indicates a malformed or invalid topic name.
    #[error("Invalid topic name: {0}")]
    InvalidTopicName(String),

    /// Indicates a malformed or invalid topic filter.
    #[error("Invalid topic filter: {0}")]
    InvalidTopicFilter(String),

    /// Indicates invalid UTF-8 data in string fields.
    #[error("Invalid UTF-8 data in string field")]
    InvalidUtf8,

    /// Wraps an I/O error that occurred during network operations.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Indicates a malformed variable byte integer encoding.
    #[error("Malformed variable byte integer encoding")]
    MalformedVariableByteInteger,

    /// Indicates a general malformed packet structure.
    #[error("Malformed packet structure")]
    MalformedPacket,

    /// Indicates that the payload must contain at least one return code but was empty.
    #[error("The payload of packet must contain at least one return code")]
    NoCodes,

    /// Indicates insufficient bytes to complete packet framing.
    #[error("Insufficient bytes to frame packet: expected at least {0} more bytes")]
    NotEnoughBytes(usize),

    /// Indicates that the payload must contain at least one topic filter but was empty.
    #[error("The payload of packet must contain at least one topic filter")]
    NoTopic,

    /// Indicates that the outgoing payload exceeds the configured size limit.
    #[error("Outgoing payload size limit exceeded: {0} bytes")]
    OutgoingPayloadSizeLimitExceeded(usize),

    /// Indicates an out-of-bounds access during packet parsing.
    #[error("Out of bounds access during packet parsing")]
    OutOfBounds,

    /// Indicates that the payload exceeds the maximum allowed size.
    #[error("Payload too large for the current configuration")]
    PayloadTooLarge,

    /// Indicates that a payload is required for this packet type but was missing.
    #[error("Payload required for this packet type")]
    PayloadRequired,

    /// Indicates that the payload exceeds the general size limit.
    #[error("Payload size limit exceeded: {0} bytes")]
    PayloadSizeLimitExceeded(usize),

    /// Indicates a general protocol violation error.
    #[error("Protocol violation detected")]
    ProtocolError,

    /// Indicates a mismatch between expected and actual protocol versions.
    #[error("Protocol version mismatch")]
    ProtocolMismatch,

    /// Indicates that the requested protocol is not supported.
    #[error("Protocol not supported by this implementation")]
    ProtocolNotSupported,

    /// Indicates a mismatch between expected and actual properties.
    #[error("Property mismatch between expected and received values")]
    PropertyMismatch,

    /// Indicates that a string exceeds the maximum allowed length.
    #[error("String exceeds maximum allowed length")]
    StringTooLong,
}
