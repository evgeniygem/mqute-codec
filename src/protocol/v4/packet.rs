use crate::codec::{Decode, Encode, RawPacket};
use crate::packet::PacketType;
use crate::Error;
use bytes::BytesMut;

use super::{
    ConnAck, Connect, Disconnect, PingReq, PingResp, PubAck, PubComp, PubRec, PubRel, Publish,
    SubAck, Subscribe, UnsubAck, Unsubscribe,
};

pub enum Packet {
    Connect(Connect),
    ConnAck(ConnAck),
    Publish(Publish),
    PubAck(PubAck),
    PubRec(PubRec),
    PubRel(PubRel),
    PubComp(PubComp),
    Subscribe(Subscribe),
    SubAck(SubAck),
    Unsubscribe(Unsubscribe),
    UnsubAck(UnsubAck),
    PingReq(PingReq),
    PingResp(PingResp),
    Disconnect(Disconnect),
}

impl Packet {
    pub fn decode(packet: RawPacket) -> Result<Self, Error> {
        let packet_type = packet.header.packet_type();

        if packet.header.remaining_len() == 0 {
            return match packet_type {
                PacketType::PingReq => Ok(Packet::PingReq(PingReq::decode(packet)?)),
                PacketType::PingResp => Ok(Packet::PingResp(PingResp::decode(packet)?)),
                PacketType::Disconnect => Ok(Packet::Disconnect(Disconnect::decode(packet)?)),
                _ => Err(Error::PayloadRequired),
            };
        }

        let decoded = match packet_type {
            PacketType::Connect => Packet::Connect(Connect::decode(packet)?),
            PacketType::ConnAck => Packet::ConnAck(ConnAck::decode(packet)?),
            PacketType::Publish => Packet::Publish(Publish::decode(packet)?),
            PacketType::PubAck => Packet::PubAck(PubAck::decode(packet)?),
            PacketType::PubRec => Packet::PubRec(PubRec::decode(packet)?),
            PacketType::PubRel => Packet::PubRel(PubRel::decode(packet)?),
            PacketType::PubComp => Packet::PubComp(PubComp::decode(packet)?),
            PacketType::Subscribe => Packet::Subscribe(Subscribe::decode(packet)?),
            PacketType::SubAck => Packet::SubAck(SubAck::decode(packet)?),
            PacketType::Unsubscribe => Packet::Unsubscribe(Unsubscribe::decode(packet)?),
            PacketType::UnsubAck => Packet::UnsubAck(UnsubAck::decode(packet)?),

            // 'PingReq', 'PingResp' or 'Disconnect' packets have no payload
            _ => return Err(Error::MalformedPacket),
        };

        Ok(decoded)
    }

    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        match self {
            Self::Connect(packet) => packet.encode(buf),
            Self::ConnAck(packet) => packet.encode(buf),
            Self::Publish(packet) => packet.encode(buf),
            Self::PubAck(packet) => packet.encode(buf),
            Self::PubRec(packet) => packet.encode(buf),
            Self::PubRel(packet) => packet.encode(buf),
            Self::PubComp(packet) => packet.encode(buf),
            Self::Subscribe(packet) => packet.encode(buf),
            Self::SubAck(packet) => packet.encode(buf),
            Self::Unsubscribe(packet) => packet.encode(buf),
            Self::UnsubAck(packet) => packet.encode(buf),
            Self::PingReq(packet) => packet.encode(buf),
            Self::PingResp(packet) => packet.encode(buf),
            Self::Disconnect(packet) => packet.encode(buf),
        }
    }
}
