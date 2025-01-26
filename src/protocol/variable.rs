use crate::codec::util::{decode_byte, decode_string, decode_word, encode_string};
use crate::protocol::version::Protocol;
use crate::{Error, QoS};
use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectHeader {
    pub protocol: Protocol,
    pub flags: u8,
    pub keep_alive: u16,
}

impl ConnectHeader {
    pub fn new(protocol: Protocol, flags: u8, keep_alive: u16) -> Self {
        ConnectHeader {
            protocol,
            flags,
            keep_alive,
        }
    }

    pub fn decode(header: &mut Bytes) -> Result<Self, Error> {
        let protocol_name = decode_string(header)?;

        let protocol: Protocol = header.get_u8().try_into()?;

        if protocol_name != protocol.name() {
            return Err(Error::InvalidProtocolName(protocol_name));
        }

        let flags = decode_byte(header)?;
        let keep_alive = decode_word(header)?;

        Ok(ConnectHeader {
            protocol,
            flags,
            keep_alive,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        // Encode the protocol name
        encode_string(buf, self.protocol.name());

        // Add the protocol level
        buf.put_u8(self.protocol.into());

        // Add the flags
        buf.put_u8(self.flags);

        // Add the keep alive timeout
        buf.put_u16(self.keep_alive);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublishHeader {
    pub topic: String,
    pub packet_id: u16,
}

impl PublishHeader {
    pub fn new<T: Into<String>>(topic: T, packet_id: u16) -> Self {
        PublishHeader {
            topic: topic.into(),
            packet_id,
        }
    }

    pub fn decode(payload: &mut Bytes, qos: QoS) -> Result<Self, Error> {
        let topic = decode_string(payload)?;

        let packet_id = match qos {
            QoS::AtMostOnce => 0,
            QoS::AtLeastOnce | QoS::ExactlyOnce => decode_word(payload)?,
        };

        if qos != QoS::AtMostOnce && packet_id == 0 {
            return Err(Error::MalformedPacket);
        }

        Ok(PublishHeader::new(topic, packet_id))
    }

    pub fn encode(&self, buf: &mut BytesMut, qos: QoS) {
        encode_string(buf, &self.topic);

        // The Packet Identifier field is only present in PUBLISH Packets where
        // the QoS level is 1 or 2
        if qos != QoS::AtMostOnce {
            buf.put_u16(self.packet_id);
        }
    }
}
