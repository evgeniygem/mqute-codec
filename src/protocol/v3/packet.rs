use crate::protocol::common::util::packet;

use crate::protocol::v4::{
    Disconnect, PingReq, PingResp, PubAck, PubComp, PubRec, PubRel, Publish, Subscribe, UnsubAck,
    Unsubscribe,
};

use super::{ConnAck, Connect, SubAck};

// Implement V3 packet
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
