use crate::error::Error;
use crate::packet::PacketType;
use crate::util::build_control_byte;
use crate::{codec, util};
use bytes::{Buf, BufMut, BytesMut};

pub(crate) struct FixedHeader {
    control_byte: u8,
    remaining_len: usize,
}

impl FixedHeader {
    pub fn new(packet: PacketType, flags: u8, remaining_len: usize) -> Self {
        let control_byte = build_control_byte(packet, flags);

        FixedHeader {
            control_byte,
            remaining_len,
        }
    }

    pub fn try_from(control_byte: u8, remaining_len: usize) -> Result<Self, Error> {
        // Packet type check
        let _: PacketType = util::fetch_packet_type(control_byte).try_into()?;

        Ok(FixedHeader {
            control_byte,
            remaining_len,
        })
    }

    pub fn packet_type(&self) -> PacketType {
        util::fetch_packet_type(self.control_byte)
            .try_into()
            .unwrap()
    }

    pub fn flags(&self) -> u8 {
        util::fetch_flags(self.control_byte)
    }

    pub fn remaining_len(&self) -> usize {
        self.remaining_len
    }

    pub fn fixed_len(&self) -> usize {
        util::remaining_len_bytes(self.remaining_len) + 1
    }

    pub fn packet_len(&self) -> usize {
        self.remaining_len + self.fixed_len()
    }

    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        buf.put_u8(self.control_byte);
        codec::util::encode_remaining_length(buf, self.remaining_len)
    }

    pub fn decode(buf: &[u8], inbound_max_size: Option<usize>) -> Result<Self, Error> {
        // At least 2 bytes are necessary to frame a packet
        let buf_len = buf.len();
        if buf_len < 2 {
            return Err(Error::NotEnoughBytes(2 - buf_len));
        }

        let mut buf = buf;
        let control_byte = buf.get_u8();
        let remaining_len = codec::util::decode_remaining_length(buf)?;

        let header = FixedHeader::try_from(control_byte, remaining_len)?;

        // Prevent unauthorized connections from attacking with huge payloads
        if let Some(max_size) = inbound_max_size {
            if header.remaining_len > max_size {
                return Err(Error::PayloadSizeLimitExceeded(header.remaining_len));
            }
        }

        let packet_len = header.packet_len();
        if buf_len < packet_len {
            return Err(Error::NotEnoughBytes(packet_len - buf_len));
        }

        Ok(header)
    }
}
