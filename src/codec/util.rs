use crate::error::Error;
use bytes::{Buf, BufMut, Bytes, BytesMut};

const PAYLOAD_MAX_SIZE: usize = 268_435_455;

pub fn decode_byte(buf: &mut Bytes) -> Result<u8, Error> {
    if buf.is_empty() {
        return Err(Error::MalformedPacket);
    }

    // Big endian
    Ok(buf.get_u8())
}

pub fn decode_word(buf: &mut Bytes) -> Result<u16, Error> {
    if buf.len() < 2 {
        return Err(Error::MalformedPacket);
    }

    // Big endian
    Ok(buf.get_u16())
}

pub fn decode_bytes(buf: &mut Bytes) -> Result<Bytes, Error> {
    let len = decode_word(buf)? as usize;
    if len > buf.len() {
        return Err(Error::OutOfBounds);
    }

    Ok(buf.split_to(len))
}

pub fn decode_string(buf: &mut Bytes) -> Result<String, Error> {
    let bytes = decode_bytes(buf)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidUtf8)
}

pub fn encode_bytes(buf: &mut BytesMut, bytes: &[u8]) {
    buf.put_u16(bytes.len() as u16);
    buf.extend_from_slice(bytes);
}

pub fn encode_string<T: AsRef<str>>(buf: &mut BytesMut, s: T) {
    encode_bytes(buf, s.as_ref().as_bytes());
}

pub fn encode_remaining_length(buf: &mut BytesMut, len: usize) -> Result<(), Error> {
    if len > PAYLOAD_MAX_SIZE {
        return Err(Error::PayloadTooLarge);
    }

    let mut done = false;
    let mut x = len;

    while !done {
        let mut byte = (x % 128) as u8;
        x /= 128;
        if x > 0 {
            byte |= 128;
        }

        buf.put_u8(byte);
        done = x == 0;
    }

    Ok(())
}

pub fn decode_remaining_length(buf: &[u8]) -> Result<usize, Error> {
    let mut len: usize = 0;
    let mut done = false;
    let mut shift = 0;

    for &value in buf {
        let byte = value as usize;
        len += (byte & 0x7F) << shift;

        // stop when continue bit is 0
        done = (byte & 0x80) == 0;
        if done {
            break;
        }

        shift += 7;

        if shift > 21 {
            return Err(Error::MalformedRemainingLength);
        }
    }

    // Not enough bytes to frame remaining length
    if !done {
        return Err(Error::NotEnoughBytes(1));
    }

    Ok(len)
}
