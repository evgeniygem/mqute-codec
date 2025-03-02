use crate::codec::util::{decode_string, encode_string};
use crate::Error;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::borrow::Borrow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Codes<T>(Vec<T>);

impl<T> Codes<T>
where
    T: TryFrom<u8, Error = Error> + Into<u8> + Copy,
{
    pub fn new<I: IntoIterator<Item = T>>(codes: I) -> Self {
        let values: Vec<T> = codes.into_iter().collect();

        if values.is_empty() {
            panic!("At least one code is required");
        }

        Codes(values)
    }

    pub(crate) fn decode(payload: &mut Bytes) -> Result<Self, Error> {
        let mut codes: Vec<T> = Vec::with_capacity(payload.len());
        while payload.has_remaining() {
            codes.push(payload.get_u8().try_into()?);
        }

        if codes.is_empty() {
            return Err(Error::NoCodes);
        }

        Ok(codes.into())
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        self.0.iter().for_each(|&value| {
            buf.put_u8(value.into());
        });
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T> AsRef<Vec<T>> for Codes<T> {
    #[inline]
    fn as_ref(&self) -> &Vec<T> {
        self.0.as_ref()
    }
}

impl<T> Borrow<Vec<T>> for Codes<T> {
    fn borrow(&self) -> &Vec<T> {
        self.0.as_ref()
    }
}

impl<T> IntoIterator for Codes<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T> FromIterator<T> for Codes<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Codes(Vec::from_iter(iter))
    }
}

impl<T> Into<Vec<T>> for Codes<T> {
    #[inline]
    fn into(self) -> Vec<T> {
        self.0
    }
}

impl<T> From<Vec<T>> for Codes<T> {
    #[inline]
    fn from(value: Vec<T>) -> Self {
        Codes(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicFilters(Vec<String>);

impl TopicFilters {
    pub fn new<T: IntoIterator<Item = String>>(filters: T) -> Self {
        let values: Vec<String> = filters.into_iter().collect();

        if values.is_empty() {
            panic!("At least one topic filter is required");
        }

        TopicFilters(values)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn decode(payload: &mut Bytes) -> Result<Self, Error> {
        let mut filters = Vec::with_capacity(1);

        while payload.has_remaining() {
            let filter = decode_string(payload)?;

            filters.push(filter);
        }

        if filters.is_empty() {
            return Err(Error::NoTopic);
        }

        Ok(TopicFilters(filters))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        self.0.iter().for_each(|filter| {
            encode_string(buf, filter);
        });
    }

    pub(crate) fn encoded_len(&self) -> usize {
        self.0.iter().fold(0, |acc, filter| acc + 2 + filter.len())
    }
}

impl AsRef<Vec<String>> for TopicFilters {
    #[inline]
    fn as_ref(&self) -> &Vec<String> {
        self.0.as_ref()
    }
}

impl Borrow<Vec<String>> for TopicFilters {
    fn borrow(&self) -> &Vec<String> {
        self.0.as_ref()
    }
}

impl IntoIterator for TopicFilters {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl FromIterator<String> for TopicFilters {
    fn from_iter<T: IntoIterator<Item = String>>(iter: T) -> Self {
        TopicFilters(Vec::from_iter(iter))
    }
}

impl Into<Vec<String>> for TopicFilters {
    #[inline]
    fn into(self) -> Vec<String> {
        self.0
    }
}

impl From<Vec<String>> for TopicFilters {
    #[inline]
    fn from(value: Vec<String>) -> Self {
        TopicFilters(value)
    }
}
