use crate::protocol::common::util::packet;

use super::{
    ConnAck, Connect, Disconnect, PingReq, PingResp, PubAck, PubComp, PubRec, PubRel, Publish,
    SubAck, Subscribe, UnsubAck, Unsubscribe,
};

// Implement V4 packet
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
