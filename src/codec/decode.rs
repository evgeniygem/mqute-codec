use super::RawPacket;
use crate::Error;

pub trait Decode: Sized {
    fn decode(packet: RawPacket) -> Result<Self, Error>;
}
