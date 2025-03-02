use crate::Error;
use bytes::{Bytes, BytesMut};

pub(crate) trait ConnectFrame {
    fn encoded_len(&self) -> usize;

    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error>;

    fn decode(buf: &mut Bytes) -> Result<Self, Error>
    where
        Self: Sized;
}

pub(crate) trait WillFrame {
    fn encoded_len(&self) -> usize;

    fn update_flags(&self, flags: &mut u8);

    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error>;

    fn decode(buf: &mut Bytes, flags: u8) -> Result<Option<Self>, Error>
    where
        Self: Sized;
}
