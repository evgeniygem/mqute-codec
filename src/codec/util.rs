use crate::Error;
use bytes::{Buf, BufMut, Bytes, BytesMut};

const PAYLOAD_MAX_SIZE: u32 = 268_435_455;

/// Decodes byte
pub(crate) fn decode_byte(buf: &mut Bytes) -> Result<u8, Error> {
    if buf.is_empty() {
        return Err(Error::MalformedPacket);
    }

    Ok(buf.get_u8())
}

/// Decodes u16
pub(crate) fn decode_word(buf: &mut Bytes) -> Result<u16, Error> {
    if buf.len() < 2 {
        return Err(Error::MalformedPacket);
    }

    Ok(buf.get_u16())
}

/// Decodes u32
pub(crate) fn decode_dword(buf: &mut Bytes) -> Result<u32, Error> {
    if buf.len() < 4 {
        return Err(Error::MalformedPacket);
    }

    Ok(buf.get_u32())
}

/// Decodes a byte array
pub(crate) fn decode_bytes(buf: &mut Bytes) -> Result<Bytes, Error> {
    let len = decode_word(buf)? as usize;
    if len > buf.len() {
        return Err(Error::OutOfBounds);
    }

    Ok(buf.split_to(len))
}

/// Decodes a UTF-8 valid string
pub(crate) fn decode_string(buf: &mut Bytes) -> Result<String, Error> {
    let bytes = decode_bytes(buf)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidUtf8)
}

/// Encodes a byte array
pub(crate) fn encode_bytes(buf: &mut BytesMut, bytes: &[u8]) {
    buf.put_u16(bytes.len() as u16);
    buf.extend_from_slice(bytes);
}

/// Encodes a UTF-8 valid string
pub(crate) fn encode_string<T: AsRef<str>>(buf: &mut BytesMut, s: T) {
    encode_bytes(buf, s.as_ref().as_bytes());
}

/// Encodes a variable byte integer
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

/// Decodes a variable byte integer
pub(crate) fn decode_variable_integer(buf: &[u8]) -> Result<u32, Error> {
    let mut value = 0u32;
    let mut done = false;
    let mut shift = 0;
    let mut consumed = 0usize;

    for &byte in buf {
        value += (byte as u32 & 0x7F) << shift;
        consumed += 1;

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

    // The MQTT spec requires the Variable Byte Integer to be encoded using the
    // minimum number of bytes necessary. Callers rely on `len_bytes(value)` to
    // know how many bytes this integer occupied on the wire (e.g. to skip past
    // it), so an overlong/non-canonical encoding here would desynchronize the
    // rest of the parser. Reject it explicitly instead.
    if consumed != crate::protocol::util::len_bytes(value as usize) {
        return Err(Error::MalformedVariableByteInteger);
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variable_integer_round_trip_boundaries() {
        // One value per byte-length boundary from the MQTT spec.
        let values = [0u32, 1, 127, 128, 16_383, 16_384, 2_097_151, 2_097_152, 268_435_455];

        for &value in &values {
            let mut buf = BytesMut::new();
            encode_variable_integer(&mut buf, value).unwrap();
            assert_eq!(buf.len(), crate::protocol::util::len_bytes(value as usize));

            let decoded = decode_variable_integer(&buf).unwrap();
            assert_eq!(decoded, value, "round trip failed for {value}");
        }
    }

    #[test]
    fn encode_rejects_value_above_max() {
        let mut buf = BytesMut::new();
        let result = encode_variable_integer(&mut buf, PAYLOAD_MAX_SIZE + 1);
        assert!(matches!(result, Err(Error::PayloadTooLarge)));
    }

    #[test]
    fn decode_rejects_non_canonical_zero() {
        // 0 encoded using 2 bytes instead of the minimal 1 byte.
        let buf = [0x80, 0x00];
        let result = decode_variable_integer(&buf);
        assert!(matches!(result, Err(Error::MalformedVariableByteInteger)));
    }

    #[test]
    fn decode_rejects_non_canonical_padded_value() {
        // 10 encoded using 2 bytes instead of the minimal 1 byte.
        let buf = [0x8A, 0x00];
        let result = decode_variable_integer(&buf);
        assert!(matches!(result, Err(Error::MalformedVariableByteInteger)));
    }

    #[test]
    fn decode_rejects_more_than_four_bytes() {
        let buf = [0xFF, 0xFF, 0xFF, 0xFF, 0x01];
        let result = decode_variable_integer(&buf);
        assert!(matches!(result, Err(Error::MalformedVariableByteInteger)));
    }

    #[test]
    fn decode_reports_not_enough_bytes() {
        let buf = [0x80];
        let result = decode_variable_integer(&buf);
        assert!(matches!(result, Err(Error::NotEnoughBytes(_))));
    }

    #[test]
    fn decode_accepts_maximal_four_byte_value() {
        let buf = [0xFF, 0xFF, 0xFF, 0x7F];
        let decoded = decode_variable_integer(&buf).unwrap();
        assert_eq!(decoded, PAYLOAD_MAX_SIZE);
    }
}
