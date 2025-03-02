use crate::Error;
use bytes::{Buf, BufMut, Bytes, BytesMut};

const PAYLOAD_MAX_SIZE: u32 = 268_435_455;

pub(crate) fn decode_byte(buf: &mut Bytes) -> Result<u8, Error> {
    if buf.is_empty() {
        return Err(Error::MalformedPacket);
    }

    // Big endian
    Ok(buf.get_u8())
}

pub(crate) fn decode_word(buf: &mut Bytes) -> Result<u16, Error> {
    if buf.len() < 2 {
        return Err(Error::MalformedPacket);
    }

    // Big endian
    Ok(buf.get_u16())
}

pub(crate) fn decode_dword(buf: &mut Bytes) -> Result<u32, Error> {
    if buf.len() < 4 {
        return Err(Error::MalformedPacket);
    }

    // Big endian
    Ok(buf.get_u32())
}

pub(crate) fn decode_bytes(buf: &mut Bytes) -> Result<Bytes, Error> {
    let len = decode_word(buf)? as usize;
    if len > buf.len() {
        return Err(Error::OutOfBounds);
    }

    Ok(buf.split_to(len))
}

pub(crate) fn decode_string(buf: &mut Bytes) -> Result<String, Error> {
    let bytes = decode_bytes(buf)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidUtf8)
}

pub(crate) fn encode_bytes(buf: &mut BytesMut, bytes: &[u8]) {
    buf.put_u16(bytes.len() as u16);
    buf.extend_from_slice(bytes);
}

pub(crate) fn encode_string<T: AsRef<str>>(buf: &mut BytesMut, s: T) {
    encode_bytes(buf, s.as_ref().as_bytes());
}

pub(crate) fn encode_variable_integer(buf: &mut BytesMut, value: u32) -> Result<(), Error> {
    if value > PAYLOAD_MAX_SIZE {
        return Err(Error::PayloadTooLarge);
    }

    let mut done = false;
    let mut x = value;

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

pub(crate) fn decode_variable_integer(buf: &[u8]) -> Result<u32, Error> {
    let mut value = 0u32;
    let mut done = false;
    let mut shift = 0;

    for &byte in buf {
        value += (byte as u32 & 0x7F) << shift;

        // stop when continue bit is 0
        done = (byte & 0x80) == 0;
        if done {
            break;
        }

        shift += 7;

        if shift > 21 {
            return Err(Error::MalformedVariableByteInteger);
        }
    }

    // Not enough bytes to decode variable byte integer
    if !done {
        return Err(Error::NotEnoughBytes(1));
    }

    Ok(value)
}
