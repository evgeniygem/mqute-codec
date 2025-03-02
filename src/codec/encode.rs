use crate::protocol::util;
use crate::Error;
use bytes::BytesMut;

pub trait Encode {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error>;
    fn payload_len(&self) -> usize;
}

pub trait Encoded: Encode {
    fn encoded_len(&self) -> usize;
}

impl<T> Encoded for T
where
    T: Encode,
{
    fn encoded_len(&self) -> usize {
        let len = self.payload_len();
        1 + util::len_bytes(len) + len
    }
}
