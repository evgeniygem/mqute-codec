//! # MQTT Packet V3
//!
//! This module implements the MQTT v3 (3.1) packet types using the `packet!` macro.
//! It defines a unified `Packet` enum that encapsulates all MQTT packet types supported
//! in the v3 protocol.

use crate::protocol::common::util::packet;

use crate::protocol::v4::{
    Disconnect, PingReq, PingResp, PubAck, PubComp, PubRec, PubRel, Publish, Subscribe, UnsubAck,
    Unsubscribe,
};

use super::{ConnAck, Connect, SubAck};

/// Represents an MQTT v3 (3.1) packet.
///
/// The `Packet` enum encapsulates all MQTT packet types supported in the v3 protocol.
/// It is generated using the `packet!` macro, which provides methods for encoding and decoding
/// MQTT packets.
///
/// The `Packet` enum includes the following variants:
/// - `Connect(Connect)`: Represents a `CONNECT` packet.
/// - `ConnAck(ConnAck)`: Represents a `CONNACK` packet.
/// - `Publish(Publish)`: Represents a `PUBLISH` packet.
/// - `PubAck(PubAck)`: Represents a `PUBACK` packet.
/// - `PubRec(PubRec)`: Represents a `PUBREC` packet.
/// - `PubRel(PubRel)`: Represents a `PUBREL` packet.
/// - `PubComp(PubComp)`: Represents a `PUBCOMP` packet.
/// - `Subscribe(Subscribe)`: Represents a `SUBSCRIBE` packet.
/// - `SubAck(SubAck)`: Represents a `SUBACK` packet.
/// - `Unsubscribe(Unsubscribe)`: Represents an `UNSUBSCRIBE` packet.
/// - `UnsubAck(UnsubAck)`: Represents an `UNSUBACK` packet.
/// - `PingReq(PingReq)`: Represents a `PINGREQ` packet.
/// - `PingResp(PingResp)`: Represents a `PINGRESP` packet.
/// - `Disconnect(Disconnect)`: Represents a `DISCONNECT` packet.
///
/// # Examples
///
/// ```rust
/// use bytes::Bytes;
/// use mqute_codec::protocol::Flags;
/// use mqute_codec::protocol::v3::Packet;
/// use mqute_codec::protocol::v3::Publish;
///
/// // Create a Publish packet
/// let publish_packet = Packet::Publish(
///     Publish::new("topic", 1u16, Bytes::new(), Flags::default()));
/// ```
packet!(
    Packet,
    Connect,
    ConnAck,
    Publish,
    PubAck,
    PubRec,
    PubRel,
    PubComp,
    Subscribe,
    SubAck,
    Unsubscribe,
    UnsubAck,
    PingReq,
    PingResp,
    Disconnect
);
