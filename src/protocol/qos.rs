//! # Quality of Service (QoS)
//!
//! This module provides an enum to represent the Quality of Service (QoS) levels
//! in the MQTT protocol and utilities for converting between QoS levels and their
//! corresponding numeric values.
//!
//! The `QoS` enum represents the three levels of Quality of Service in MQTT:
//! - `AtMostOnce`: QoS level 0 (Fire and Forget)
//! - `AtLeastOnce`: QoS level 1 (Acknowledged Delivery)
//! - `ExactlyOnce`: QoS level 2 (Assured Delivery)

use crate::Error;

/// Represents the Quality of Service (QoS) levels in MQTT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub enum QoS {
    /// QoS level 0: At most once delivery (Fire and Forget).
    ///
    /// The message is delivered according to the best efforts of the underlying network.
    /// No acknowledgment is sent, and the message is not stored or re-transmitted.
    AtMostOnce = 0,
    /// QoS level 1: At least once delivery (Acknowledged Delivery).
    ///
    /// The message is assured to arrive but may arrive more than once.
    AtLeastOnce = 1,
    /// QoS level 2: Exactly once delivery (Assured Delivery).
    ///
    /// The message is assured to arrive exactly once.
    ExactlyOnce = 2,
}

impl TryFrom<u8> for QoS {
    type Error = Error;

    /// Attempts to convert a numeric value into a `QoS` enum.
    ///
    /// # Errors
    /// Returns an `Error::InvalidQos` if the value is not a valid QoS level.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::protocol::QoS;
    /// use mqute_codec::Error;
    ///
    /// let qos = QoS::try_from(1).unwrap();
    /// assert_eq!(qos, QoS::AtLeastOnce);
    ///
    /// let result = QoS::try_from(3);
    /// assert!(result.is_err());
    /// ```
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(QoS::AtMostOnce),
            1 => Ok(QoS::AtLeastOnce),
            2 => Ok(QoS::ExactlyOnce),
            n => Err(Error::InvalidQos(n)),
        }
    }
}

impl From<QoS> for u8 {
    /// Converts the `QoS` enum into its corresponding numeric value.
    ///
    /// # Examples
    ///
    /// ```
    /// use mqute_codec::protocol::QoS;
    ///
    /// let qos = QoS::ExactlyOnce;
    /// let value: u8 = qos.into();
    /// assert_eq!(value, 2);
    /// ```
    fn from(value: QoS) -> Self {
        value as u8
    }
}
