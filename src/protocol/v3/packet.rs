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
// The `Packet` enum encapsulates all MQTT packet types supported in the v3 protocol.
// It is generated using the `packet!` macro, which provides methods for encoding and decoding
// MQTT packets.
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
