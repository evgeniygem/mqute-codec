use super::util;
use crate::protocol::PacketType;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PingReq {}

util::ping_packet_decode_impl!(PingReq, PacketType::PingReq);
util::ping_packet_encode_impl!(PingReq, PacketType::PingReq);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PingResp {}

util::ping_packet_decode_impl!(PingResp, PacketType::PingResp);
util::ping_packet_encode_impl!(PingResp, PacketType::PingResp);
