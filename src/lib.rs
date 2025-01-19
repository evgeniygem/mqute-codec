mod codec;
mod error;
mod header;
mod packet;
mod protocol;
mod qos;
mod util;

use error::Error;

/// Protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    V3,
    V4,
    V5,
}

impl Into<u8> for Protocol {
    fn into(self) -> u8 {
        match self {
            Protocol::V3 => 0x03,
            Protocol::V4 => 0x04,
            Protocol::V5 => 0x05,
        }
    }
}

impl TryFrom<u8> for Protocol {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x03 => Ok(Protocol::V3),
            0x04 => Ok(Protocol::V4),
            0x05 => Ok(Protocol::V5),
            _ => Err(Error::InvalidProtocolLevel(value)),
        }
    }
}

impl Protocol {
    pub fn name(self) -> &'static str {
        match self {
            Protocol::V3 => "MQIsdp",
            // Same for V4 and V5
            _ => "MQTT",
        }
    }
}
