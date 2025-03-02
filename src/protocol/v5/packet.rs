use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::v5::{
    Auth, ConnAck, Connect, Disconnect, PingReq, PingResp, PubAck, PubComp, PubRec, PubRel,
    Publish, SubAck, Subscribe, UnsubAck, Unsubscribe,
};
use crate::protocol::PacketType;
use crate::Error;

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
    Auth(Auth),
}

impl Packet {
    pub fn decode(raw_packet: RawPacket) -> Result<Self, Error> {
        let packet_type = raw_packet.header.packet_type();

        if raw_packet.header.remaining_len() == 0 {
            return match packet_type {
                PacketType::PingReq => Ok(Self::PingReq(PingReq::decode(raw_packet)?)),
                PacketType::PingResp => Ok(Self::PingResp(PingResp::decode(raw_packet)?)),
                PacketType::Disconnect => Ok(Self::Disconnect(Disconnect::decode(raw_packet)?)),
                PacketType::Auth => Ok(Self::Auth(Auth::decode(raw_packet)?)),
                _ => Err(Error::PayloadRequired),
            };
        }

        let decoded = match packet_type {
            PacketType::Connect => Self::Connect(Connect::decode(raw_packet)?),
            PacketType::ConnAck => Self::ConnAck(ConnAck::decode(raw_packet)?),
            PacketType::Publish => Self::Publish(Publish::decode(raw_packet)?),
            PacketType::PubAck => Self::PubAck(PubAck::decode(raw_packet)?),
            PacketType::PubRec => Self::PubRec(PubRec::decode(raw_packet)?),
            PacketType::PubRel => Self::PubRel(PubRel::decode(raw_packet)?),
            PacketType::PubComp => Self::PubComp(PubComp::decode(raw_packet)?),
            PacketType::Subscribe => Self::Subscribe(Subscribe::decode(raw_packet)?),
            PacketType::SubAck => Self::SubAck(SubAck::decode(raw_packet)?),
            PacketType::Unsubscribe => Self::Unsubscribe(Unsubscribe::decode(raw_packet)?),
            PacketType::UnsubAck => Self::UnsubAck(UnsubAck::decode(raw_packet)?),
            PacketType::Disconnect => Self::Disconnect(Disconnect::decode(raw_packet)?),
            PacketType::Auth => Self::Auth(Auth::decode(raw_packet)?),
            // 'PingReq', 'PingResp' packets have no payload
            _ => return Err(Error::MalformedPacket),
        };

        Ok(decoded)
    }

    pub fn encode(&self, buf: &mut bytes::BytesMut) -> Result<(), Error> {
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
            Self::Auth(packet) => packet.encode(buf),
        }
    }
}
