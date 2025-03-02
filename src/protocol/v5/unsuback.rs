use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::v5::reason::ReasonCode;
use crate::protocol::v5::util::{ack_properties, ack_properties_frame_impl, id_header};
use crate::protocol::{Codes, FixedHeader, PacketType};
use crate::Error;
use bytes::{Buf, Bytes, BytesMut};

ack_properties!(UnsubAckProperties);
ack_properties_frame_impl!(UnsubAckProperties);

fn validate_unsuback_reason_code(code: ReasonCode) -> bool {
    matches!(code.into(), 0 | 17 | 128 | 131 | 135 | 143 | 145)
}

id_header!(UnsubAckHeader, UnsubAckProperties);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsubAck {
    header: UnsubAckHeader,
    codes: Codes<ReasonCode>,
}

impl UnsubAck {
    pub fn new<T>(packet_id: u16, properties: Option<UnsubAckProperties>, codes: T) -> Self
    where
        T: IntoIterator<Item = ReasonCode> + Iterator<Item = ReasonCode>,
    {
        let codes: Vec<ReasonCode> = codes.into_iter().collect();

        if codes.is_empty() {
            panic!("At least one reason code is required");
        }

        if !codes
            .iter()
            .all(|&code| validate_unsuback_reason_code(code))
        {
            panic!("Invalid reason code");
        }

        let header = UnsubAckHeader::new(packet_id, properties);

        UnsubAck {
            header,
            codes: codes.into(),
        }
    }

    pub fn packet_id(&self) -> u16 {
        self.header.packet_id
    }

    pub fn code(&self) -> Codes<ReasonCode> {
        self.codes.clone()
    }

    pub fn properties(&self) -> Option<UnsubAckProperties> {
        self.header.properties.clone()
    }
}

impl Encode for UnsubAck {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::UnsubAck, self.payload_len());
        header.encode(buf)?;

        self.header.encode(buf)?;
        self.codes.encode(buf);
        Ok(())
    }

    fn payload_len(&self) -> usize {
        self.header.encoded_len() + self.codes.len()
    }
}

impl Decode for UnsubAck {
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::UnsubAck
            || !packet.header.flags().is_default()
        {
            return Err(Error::MalformedPacket);
        }

        let header = UnsubAckHeader::decode(&mut packet.payload)?;
        let codes = Codes::decode(&mut packet.payload)?;

        let codes: Vec<ReasonCode> = codes.into();

        if !codes
            .iter()
            .all(|&code| validate_unsuback_reason_code(code))
        {
            return Err(Error::MalformedPacket);
        }

        Ok(UnsubAck {
            header,
            codes: codes.into(),
        })
    }
}
