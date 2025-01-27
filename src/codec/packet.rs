use super::Encode;
use crate::protocol::FixedHeader;
use crate::Error;
use bytes::{Buf, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Clone)]
pub struct RawPacket {
    // Fixed header
    pub header: FixedHeader,

    // Variable header and payload
    pub payload: Bytes,
}

impl RawPacket {
    pub(crate) fn new(header: FixedHeader, payload: Bytes) -> Self {
        if header.remaining_len() != payload.len() {
            panic!("Header and payload mismatch");
        }
        RawPacket { header, payload }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketCodec {
    inbound_max_size: Option<usize>,
    outbound_max_size: Option<usize>,
}

impl PacketCodec {
    pub fn new(inbound_max_size: Option<usize>, outbound_max_size: Option<usize>) -> Self {
        PacketCodec {
            inbound_max_size,
            outbound_max_size,
        }
    }

    pub fn try_decode(&self, dst: &mut BytesMut) -> Result<RawPacket, Error> {
        // Decode the header and check the allowable size
        let header = FixedHeader::decode(dst, self.inbound_max_size)?;

        let mut payload = dst.split_to(header.packet_len()).freeze();

        // Skip the header data
        payload.advance(header.fixed_len());

        Ok(RawPacket::new(header, payload))
    }
}

impl<T> Encoder<T> for PacketCodec
where
    T: Encode,
{
    type Error = Error;

    fn encode(&mut self, item: T, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if let Some(max_size) = self.outbound_max_size {
            if item.encoded_len() > max_size {
                return Err(Error::OutgoingPayloadSizeLimitExceeded(item.encoded_len()));
            }
        }

        item.encode(dst)
    }
}

impl Decoder for PacketCodec {
    type Item = RawPacket;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.try_decode(src) {
            Ok(packet) => Ok(Some(packet)),
            Err(Error::NotEnoughBytes(len)) => {
                // Get more packets to construct the incomplete packet
                src.reserve(len);
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}
