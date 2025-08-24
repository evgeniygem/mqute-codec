use crate::codec::util::{decode_string, decode_word, encode_string};
use crate::protocol::{util, QoS};
use crate::Error;
use bytes::{BufMut, Bytes, BytesMut};

/// Represents the header of the MQTT Publish packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublishHeader {
    pub topic: String,
    pub packet_id: u16,
}

impl PublishHeader {
    pub(crate) fn new<T: Into<String>>(topic: T, packet_id: u16) -> Self {
        let topic = topic.into();

        // Validate topic name
        if !util::is_valid_topic_name(&topic) {
            panic!("Invalid topic name: '{}'", topic);
        }

        PublishHeader {
            topic,
            packet_id,
        }
    }

    pub(crate) fn encoded_len(&self, qos: QoS) -> usize {
        let packet_id_len = if qos == QoS::AtMostOnce { 0 } else { 2 };
        2 + self.topic.len() + packet_id_len
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut, qos: QoS) {
        encode_string(buf, &self.topic);

        // The Packet Identifier field is only present in PUBLISH Packets where
        // the QoS level is 1 or 2
        if qos != QoS::AtMostOnce {
            buf.put_u16(self.packet_id);
        }
    }

    pub(crate) fn decode(payload: &mut Bytes, qos: QoS) -> Result<Self, Error> {
        let topic = decode_string(payload)?;

        if !util::is_valid_topic_name(&topic) {
            return Err(Error::InvalidTopicName(topic));
        }

        let packet_id = match qos {
            QoS::AtMostOnce => 0,
            QoS::AtLeastOnce | QoS::ExactlyOnce => decode_word(payload)?,
        };

        if qos != QoS::AtMostOnce && packet_id == 0 {
            return Err(Error::MalformedPacket);
        }

        Ok(PublishHeader::new(topic, packet_id))
    }
}
