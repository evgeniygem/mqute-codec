//! # MQTT Packet V4
//!
//! This module defines the `Packet` enum, which represents all possible MQTT packet types
//! for the MQTT v4 (3.1.1) protocol. The `packet!` macro is used to generate the `Packet` enum
//! and its associated methods for encoding and decoding.

use crate::protocol::common::util::packet;

use super::{
    ConnAck, Connect, Disconnect, PingReq, PingResp, PubAck, PubComp, PubRec, PubRel, Publish,
    SubAck, Subscribe, UnsubAck, Unsubscribe,
};

// Represents all MQTT packet types for MQTT v4 (3.1.1).
// The `Packet` enum is generated using the `packet!` macro and includes variants for each
// MQTT packet type.
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
