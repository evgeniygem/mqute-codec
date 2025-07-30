//! # MQTT Packet Codec
//!
//! This module provides packet construction and serialization/deserialization for MQTT protocol.
//! It handles the binary representation of MQTT packets but does NOT include:
//! - Network I/O operations
//! - Protocol state management
//! - Session handling
//! - Quality of Service guarantees
//!
//! ## Responsibilities
//! - Packet structure definitions for all MQTT versions (3.1, 3.1.1, 5.0)
//! - Encoding packets to wire format
//! - Decoding packets from wire format
//! - Basic protocol validation
//!
//! ## Supported MQTT Versions
//!
//! | Version   | Specification | Status       | Notable Features |
//! |-----------|---------------|--------------|------------------|
//! | MQTT 3.1  | [MQTT 3.1]    | Full Support | Basic pub/sub, QoS 0-2 |
//! | MQTT 3.1.1| [MQTT 3.1.1]  | Full Support | Clean session, Last Will |
//! | MQTT 5.0  | [MQTT 5.0]    | Full Support | Properties, Enhanced Auth |
//!
//! [MQTT 3.1]: http://public.dhe.ibm.com/software/dw/webservices/ws-mqtt/mqtt-v3r1.html
//! [MQTT 3.1.1]: http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html
//! [MQTT 5.0]: https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html
//!
//! ## Feature Highlights
//!
//! - **Multi-Version Support**: Single API for all MQTT versions
//! - **Zero-Copy Parsing**: Maximizes performance by minimizing allocations
//! - **Protocol Bridging**: Tools for interoperability between versions
//! - **Validation**: Strict protocol compliance checking
//! - **Async Ready**: Works seamlessly with async runtimes

/// ## Codec Implementation
///
/// Contains the core encoding/decoding logic for MQTT packets.
///
/// ### Main Components
/// - `PacketCodec`: The primary codec for encoding/decoding packets
/// - `RawPacket`: Intermediate packet representation
///
/// ### Example
///
/// ```rust
/// use mqute_codec::codec::{PacketCodec, RawPacket, Encode, Decode, Encoded};
/// use tokio_util::codec::Decoder;
/// use bytes::BytesMut;
/// use mqute_codec::protocol::PacketType;
///
/// let mut codec = PacketCodec::new(Some(4096), Some(4096));
/// let mut buf = BytesMut::new();
/// buf.extend_from_slice(b"\x10\x29\x00\x04MQTT\x04\xd6\x00\x10\x00\x06client\x00\x04/abc\x00\x03bye\x00\x04user\x00\x04pass");
///
/// match codec.decode(&mut buf) {
///     Ok(Some(packet)) => {
///         assert_eq!(packet.header.packet_type(), PacketType::Connect);
///     }
///     _ => panic!("Decoding failed"),
/// }
/// ```
pub mod codec;

/// ## Protocol Implementation
///
/// Contains all MQTT packet definitions and protocol logic.
///
/// ### Organization
/// - `v3`: MQTT v3.1 protocol implementation
/// - `v4`: MQTT v3.1.1 protocol implementation
/// - `v5`: MQTT v5.0 protocol implementation
/// - `common`: Shared types between protocol versions
///
/// ### Example: Creating a CONNECT Packet
/// ```rust
/// use mqute_codec::protocol::{v5::Connect, Credentials};
///
/// let connect = Connect::new(
///     "client_id",
///     Some(Credentials::login("user", "pass")),
///     None,
///     30,  // keep alive
///     true // clean session
/// );
/// ```
///
/// ### Example: Creating a PUBLISH Packet
/// ```rust
/// use mqute_codec::protocol::v4::{Publish};
/// use mqute_codec::protocol::{Flags, QoS};
/// use bytes::Bytes;
///
/// let flag = Flags::new(QoS::AtLeastOnce);
///
/// let publish = Publish::new(
///     "topic",
///     1234,
///     Bytes::from("payload"),
///     flag
/// );
/// ```
pub mod protocol;

/// ## Error Handling
///
/// Unified error type for all codec operations.
///
/// ### Example
/// ```rust
/// use mqute_codec::{Error, codec::PacketCodec};
/// use tokio_util::codec::Decoder;
/// use bytes::BytesMut;
///
/// let mut codec = PacketCodec::new(None, None);
/// let mut buf = BytesMut::new();
/// buf.extend_from_slice(b"\x0f\x04\x00\x00\x00\x00");
///
/// match codec.decode(&mut buf) {
///     Err(Error::InvalidPacketType(_)) => println!("Got expected error"),
///     _ => panic!("Should have failed"),
/// }
/// ```
mod error;
pub use error::Error;
