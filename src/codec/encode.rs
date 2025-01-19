use crate::util;
use crate::Error;
use bytes::BytesMut;

pub trait Encode {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), Error>;

    fn payload_len(&self) -> usize;

    fn packet_len(&self) -> usize {
        let len = self.payload_len();
        1 + util::remaining_len_bytes(len) + len
    }
}
