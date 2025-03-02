use crate::codec::{Decode, Encode, RawPacket};
use crate::protocol::v5::reason::ReasonCode;
use crate::protocol::v5::util::{ack_properties, ack_properties_frame_impl, id_header};
use crate::protocol::{Codes, FixedHeader, PacketType};
use crate::Error;
use bytes::{Buf, Bytes, BytesMut};

ack_properties!(SubAckProperties);
ack_properties_frame_impl!(SubAckProperties);

fn validate_suback_reason_code(code: ReasonCode) -> bool {
    matches!(
        code.into(),
        0 | 1 | 2 | 128 | 131 | 135 | 143 | 145 | 151 | 158 | 161 | 162
    )
}

id_header!(SubAckHeader, SubAckProperties);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubAck {
    header: SubAckHeader,
    codes: Codes<ReasonCode>,
}

impl SubAck {
    pub fn new<T>(packet_id: u16, properties: Option<SubAckProperties>, codes: T) -> Self
    where
        T: IntoIterator<Item = ReasonCode> + Iterator<Item = ReasonCode>,
    {
        let codes: Vec<ReasonCode> = codes.into_iter().collect();

        if codes.is_empty() {
            panic!("At least one reason code is required");
        }

        if !codes.iter().all(|&code| validate_suback_reason_code(code)) {
            panic!("Invalid reason code");
        }

        let header = SubAckHeader::new(packet_id, properties);

        SubAck {
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

    pub fn properties(&self) -> Option<SubAckProperties> {
        self.header.properties.clone()
    }
}

impl Encode for SubAck {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let header = FixedHeader::new(PacketType::SubAck, self.payload_len());
        header.encode(buf)?;

        self.header.encode(buf)?;
        self.codes.encode(buf);
        Ok(())
    }

    fn payload_len(&self) -> usize {
        self.header.encoded_len() + self.codes.len()
    }
}

impl Decode for SubAck {
    fn decode(mut packet: RawPacket) -> Result<Self, Error> {
        if packet.header.packet_type() != PacketType::SubAck || !packet.header.flags().is_default()
        {
            return Err(Error::MalformedPacket);
        }

        let header = SubAckHeader::decode(&mut packet.payload)?;
        let mut codes: Vec<ReasonCode> = Codes::decode(&mut packet.payload)?.into();

        // Change 'Success' -> 'GrantedQos0'
        for code in codes.iter_mut() {
            if !validate_suback_reason_code(*code) {
                return Err(Error::InvalidReasonCode((*code).into()));
            }
            if (*code) == ReasonCode::Success {
                *code = ReasonCode::GrantedQos0;
            }
        }

        Ok(SubAck {
            header,
            codes: codes.into(),
        })
    }
}
