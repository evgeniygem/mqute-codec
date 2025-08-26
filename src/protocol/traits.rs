//! # MQTT Packet Traits
//!
//! This module defines auxiliary traits for all MQTT packet types. These traits provide
//! supplementary interfaces for packet handling across different protocol versions while
//! allowing version-specific implementations.
//!
//! ## Important Note: Auxiliary Nature
//!
//! These traits are **auxiliary** - they are not the primary packet encoding/decoding
//! interface. The main packet functionality is provided through the `Encode` and `Decode`
//! traits and version-specific struct implementations.

/// Auxiliary trait for MQTT CONNECT packet functionality.
pub trait Connect {}

/// Auxiliary trait for MQTT CONNACK packet functionality.
pub trait ConnAck {}

/// Auxiliary trait for MQTT PUBLISH packet functionality.
pub trait Publish {}

/// Auxiliary trait for MQTT PUBACK packet functionality.
pub trait PubAck {}

/// Auxiliary trait for MQTT PUBREC packet functionality.
pub trait PubRec {}

/// Auxiliary trait for MQTT PUBREL packet functionality.
pub trait PubRel {}

/// Auxiliary trait for MQTT PUBCOMP packet functionality.
pub trait PubComp {}

/// Auxiliary trait for MQTT SUBSCRIBE packet functionality.
pub trait Subscribe {}

/// Auxiliary trait for MQTT SUBACK packet functionality.
pub trait SubAck {}

/// Auxiliary trait for MQTT UNSUBSCRIBE packet functionality.
pub trait Unsubscribe {}

/// Auxiliary trait for MQTT UNSUBACK packet functionality.
pub trait UnsubAck {}

/// Auxiliary trait for MQTT PINGREQ packet functionality.
pub trait PingReq {}

/// Auxiliary trait for MQTT PINGRESP packet functionality.
pub trait PingResp {}

/// Auxiliary trait for MQTT DISCONNECT packet functionality.
pub trait Disconnect {}

/// Auxiliary trait for MQTT AUTH packet functionality (v5 only).
pub trait Auth {}
