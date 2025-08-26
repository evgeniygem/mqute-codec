//! # MQTT Protocol Implementation
//!
//! This module provides complete implementations of MQTT protocol versions 3.1, 3.1.1, and 5.0,
//! with shared components for packet handling and protocol logic.
//!
//! The implementation follows the official MQTT specification for each version and provides
//! type-safe APIs for building, parsing, and handling MQTT packets.
//!
//! ## Examples
//!
//! ### Working with different protocol versions
//! ```rust
//! use std::time::Duration;
//! use mqute_codec::protocol::{v4, v5, Protocol};
//! use mqute_codec::protocol::QoS;
//!
//! // Create v3.1.1 CONNECT packet
//! let connect_v4 = v4::Connect::new(
//!     "client_id",
//!     None,
//!     None,
//!     Duration::from_secs(30),
//!     true
//! );
//! assert_eq!(connect_v4.protocol(), Protocol::V4);
//!
//! // Create v5 CONNECT with properties
//! let connect_v5 = v5::Connect::new(
//!     "client_id",
//!     None,
//!     None,
//!     Duration::from_secs(30),
//!     true
//! );
//! assert_eq!(connect_v5.protocol(), Protocol::V5);
//! ```

/// # Common Protocol Components
///
/// Shared types and utilities used across all MQTT protocol versions.
/// Includes connection credentials, payload handling, and frame interfaces.
mod common;

/// # Packet Header Implementation
///
/// Handles fixed header parsing and construction for MQTT packets.
/// Manages packet type, flags, and remaining length encoding.
mod header;

/// # Core Packet Types
///
/// Defines the fundamental MQTT packet types and their implementations.
/// Includes packet encoding, decoding, and validation logic.
mod packet;

/// # Quality of Service Levels
///
/// Implements MQTT Quality of Service (QoS) levels with full specification
/// compliance.
mod qos;

/// # Protocol Utilities
///
/// Contains utility functions for MQTT protocol handling including:
/// - Topic validation and filtering
/// - Variable byte integer encoding
/// - System topic detection
pub mod util;

/// # Protocol Version Handling
///
/// Manages protocol version negotiation and feature detection.
/// Provides version-specific behavior and compatibility handling.
mod version;

/// # MQTT v3.1 Implementation
///
/// Complete implementation of the MQTT 3.1 specification (IBM version).
///
/// ## Key Features
/// - Basic QoS 0-2 support with acknowledged delivery
/// - Clean session handling for persistent connections
/// - Last Will and Testament (LWT) message support
/// - Basic authentication username/password support
pub mod v3;

/// # MQTT v3.1.1 Implementation
///
/// Implementation of MQTT 3.1.1 (OASIS Standard, most widely deployed version).
///
/// ## Differences from v3.1
/// - Enhanced error handling with specific return codes
/// - Improved session management with persistent sessions
/// - Standardized protocol name and version identification
/// - Clarified specification semantics and edge cases
pub mod v4;

/// # MQTT v5.0 Implementation
///
/// Complete implementation of MQTT 5.0 with modern features and enhancements.
///
/// ## Key Features
/// - Enhanced authentication and authorization mechanisms
/// - User properties for extensible metadata
/// - Reason codes for detailed error reporting
/// - Shared subscriptions for load balancing
/// - Message expiry and topic aliasing
/// - Flow control and quota management
pub mod v5;

/// # Auxiliary Packet Traits
///
/// Provides generic traits for MQTT packet functionality across protocol versions.
/// These auxiliary traits enable version-agnostic code while maintaining type safety.
pub mod traits;

/// Authentication credentials for MQTT connection
pub use common::Credentials;
/// Re-export common protocol types and payload handlers
pub use common::payload::*;
/// Packet header types and fixed header implementation
pub use header::*;
/// MQTT packet type definitions and identifiers
pub use packet::PacketType;
/// Quality of Service level enumeration and functionality
pub use qos::QoS;
/// Protocol version handling and negotiation
pub use version::*;
