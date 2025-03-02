use crate::protocol::util;
use crate::protocol::PacketType;
use crate::Error;
use crate::{codec, QoS};
use bytes::{Buf, BufMut, BytesMut};
use std::cmp::PartialEq;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Flags {
    pub dup: bool,
    pub qos: QoS,
    pub retain: bool,
}

impl Default for Flags {
    fn default() -> Self {
        Flags {
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
        }
    }
}

impl Flags {
    pub fn new(qos: QoS) -> Self {
        Flags {
            dup: false,
            qos,
            retain: false,
        }
    }

    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedHeader {
    control_byte: u8,
    remaining_len: usize,
}

impl FixedHeader {
    pub fn new(packet: PacketType, remaining_len: usize) -> Self {
        let control_byte = build_control_byte(packet, Flags::default());

        FixedHeader {
            control_byte,
            remaining_len,
        }
    }

    pub fn try_from(control_byte: u8, remaining_len: usize) -> Result<Self, Error> {
        // Packet type check
        let _: PacketType = fetch_packet_type(control_byte).try_into()?;

        Ok(FixedHeader {
            control_byte,
            remaining_len,
        })
    }

    pub fn with_flags(packet_type: PacketType, flags: Flags, remaining_len: usize) -> Self {
        let control_byte = build_control_byte(packet_type, flags);
        FixedHeader {
            control_byte,
            remaining_len,
        }
    }

    pub fn packet_type(&self) -> PacketType {
        fetch_packet_type(self.control_byte).try_into().unwrap()
    }

    pub fn flags(&self) -> Flags {
        let flags = self.control_byte & 0x0F;
        let dup: bool = (flags & 0x08) != 0;
        let qos = ((flags >> 1) & 0x03).try_into().unwrap();
        let retain = flags & 0x01 != 0;

        Flags { dup, qos, retain }
    }

    pub fn remaining_len(&self) -> usize {
        self.remaining_len
    }

    pub fn fixed_len(&self) -> usize {
        util::len_bytes(self.remaining_len) + 1
    }

    pub fn packet_len(&self) -> usize {
        self.remaining_len + self.fixed_len()
    }

    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        buf.put_u8(self.control_byte);
        codec::util::encode_variable_integer(buf, self.remaining_len as u32)
    }

    pub fn decode(buf: &[u8], inbound_max_size: Option<usize>) -> Result<Self, Error> {
        // At least 2 bytes are necessary to frame a packet
        let buf_len = buf.len();
        if buf_len < 2 {
            return Err(Error::NotEnoughBytes(2 - buf_len));
        }

        let mut buf = buf;
        let control_byte = buf.get_u8();
        let remaining_len = codec::util::decode_variable_integer(buf)? as usize;

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

#[inline]
fn fetch_packet_type(control_byte: u8) -> u8 {
    control_byte >> 4
}

const fn build_control_byte(packet_type: PacketType, flags: Flags) -> u8 {
    let byte = (packet_type as u8) << 4;
    let flags = (flags.dup as u8) << 3 | (flags.qos as u8) << 1 | (flags.retain as u8) << 0;
    byte | flags
}
