//! # MQTT Protocol Version
//!
//! This module provides an enum to represent the MQTT protocol versions and utilities
//! for converting between protocol versions and their corresponding numeric values.
//!
//! The `Protocol` enum represents the supported MQTT protocol versions:
//! - `V3`: MQTT v3.1 (also known as MQIsdp)
//! - `V4`: MQTT v3.1.1
//! - `V5`: MQTT v5.0
//!
//! The enum also provides methods to convert between protocol versions and their
//! numeric representations, as well as to retrieve the protocol name.

use crate::Error;

/// Represents the MQTT protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// MQTT v3.1
    V3,
    /// MQTT v3.1.1
    V4,
    /// MQTT v5.0
    V5,
}

impl Into<u8> for Protocol {
    /// Converts the `Protocol` enum into its corresponding numeric value.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::protocol::Protocol;
    ///
    /// let protocol = Protocol::V5;
    /// let value: u8 = protocol.into();
    /// assert_eq!(value, 0x05);
    /// ```
    fn into(self) -> u8 {
        match self {
            Protocol::V3 => 0x03,
            Protocol::V4 => 0x04,
            Protocol::V5 => 0x05,
        }
    }
}

impl TryFrom<u8> for Protocol {
    type Error = Error;

    /// Attempts to convert a numeric value into a `Protocol` enum.
    ///
    /// # Errors
    /// Returns an `Error::InvalidProtocolLevel` if the value is not a valid protocol version.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::protocol::Protocol;
    /// use mqute_codec::Error;
    ///
    /// let protocol = Protocol::try_from(0x04).unwrap();
    /// assert_eq!(protocol, Protocol::V4);
    ///
    /// let result = Protocol::try_from(0x06);
    /// assert!(result.is_err());
    /// ```
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x03 => Ok(Protocol::V3),
            0x04 => Ok(Protocol::V4),
            0x05 => Ok(Protocol::V5),
            _ => Err(Error::InvalidProtocolLevel(value)),
        }
    }
}

impl Protocol {
    /// Returns the protocol name as a static string.
    ///
    /// - For `Protocol::V3`, the name is `"MQIsdp"`.
    /// - For `Protocol::V4` and `Protocol::V5`, the name is `"MQTT"`.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::protocol::Protocol;
    ///
    /// let protocol = Protocol::V3;
    /// assert_eq!(protocol.name(), "MQIsdp");
    ///
    /// let protocol = Protocol::V5;
    /// assert_eq!(protocol.name(), "MQTT");
    /// ```
    pub fn name(self) -> &'static str {
        match self {
            Protocol::V3 => "MQIsdp",
            // Same for V4 and V5
            _ => "MQTT",
        }
    }
}
