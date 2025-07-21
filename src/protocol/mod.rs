//! # MQTT Protocol Implementation
//!
//! This module provides complete implementations of MQTT protocol versions 3.1, 3.1.1, and 5.0,
//! with shared components for packet handling and protocol logic.
//!
//! ## Examples
//!
//! ### Working with different protocol versions
//! ```rust
//! use mqute_codec::protocol::{v4, v5, Protocol};
//! use mqute_codec::protocol::QoS;
//!
//! // Create v3.1.1 CONNECT packet
//! let connect_v4 = v4::Connect::new(
//!     "client_id",
//!     None,
//!     None,
//!     30,
//!     true
//! );
//! assert_eq!(connect_v4.protocol(), Protocol::V4);
//!
//! // Create v5 CONNECT with properties
//! let connect_v5 = v5::Connect::new(
//!     "client_id",
//!     None,
//!     None,
//!     30,
//!     true
//! );
//! assert_eq!(connect_v5.protocol(), Protocol::V5);
//! ```

/// # Common Protocol Components
mod common;

/// # Packet Header Implementation
mod header;

/// # Core Packet Types
mod packet;

/// # Quality of Service Levels
mod qos;

/// # Protocol Utilities
pub(crate) mod util;

/// # Protocol Version Handling
mod version;

/// # MQTT v3.1 Implementation
///
/// Complete implementation of the MQTT 3.1 specification.
///
/// ## Key Features
/// - Basic QoS 0-2 support
/// - Clean session handling
/// - Will message support
pub mod v3;

/// # MQTT v3.1.1 Implementation
///
/// Implementation of MQTT 3.1.1 (OASIS Standard).
///
/// ## Differences from v3.1
/// - Enhanced error handling
/// - Improved session management
pub mod v4;

/// # MQTT v5.0 Implementation
///
/// Complete implementation of MQTT 5.0 with:
/// - Enhanced authentication
/// - User properties
/// - Reason codes
/// - Shared subscriptions
pub mod v5;

/// Re-export common protocol types
pub use common::payload::*;
pub use common::Credentials;
pub use header::*;
pub use packet::PacketType;
pub use qos::QoS;
pub use version::*;
