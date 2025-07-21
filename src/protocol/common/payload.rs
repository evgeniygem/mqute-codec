//! # Codes and Topic Filters
//!
//! This module provides utilities for handling MQTT protocol-specific data structures,
//! specifically `Codes` and `TopicFilters`. These structures are used to encode and decode
//! MQTT protocol data, such as return codes and topic filters, which are essential for
//! MQTT communication.

use crate::codec::util::{decode_string, encode_string};
use crate::Error;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::borrow::Borrow;
use std::ops::{Index, IndexMut};

/// The `Codes` module provides a generic structure to handle a collection of MQTT return codes.
/// These codes are used in various MQTT control packets, such as ConnAck, SubAck, and UnsubAck.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Codes<T>(Vec<T>);

#[allow(clippy::len_without_is_empty)]
impl<T> Codes<T>
where
    T: TryFrom<u8, Error = Error> + Into<u8> + Copy,
{
    /// Creates a new `Codes` instance from an iterator of codes.
    ///
    /// # Panics
    ///
    /// Panics if the iterator is empty, as at least one code is required.
    ///
    /// # Example
    ///
    /// ```rust
    /// use mqute_codec::protocol::{Codes, QoS};
    /// use mqute_codec::protocol::v4::ReturnCode;
    ///
    /// let values = vec![ReturnCode::Failure, ReturnCode::Success(QoS::AtLeastOnce)];
    /// let codes: Codes<ReturnCode> = Codes::new(values);
    /// ```
    pub fn new<I: IntoIterator<Item = T>>(codes: I) -> Self {
        let values: Vec<T> = codes.into_iter().collect();

        if values.is_empty() {
            panic!("At least one code is required");
        }

        Codes(values)
    }

    /// Decodes a `Codes` instance from a byte buffer.
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

    /// Encodes the `Codes` instance into a byte buffer.
    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        self.0.iter().for_each(|&value| {
            buf.put_u8(value.into());
        });
    }

    /// Returns the number of codes in the `Codes` instance.
    ///
    /// # Example
    ///
    /// ```rust
    /// use mqute_codec::protocol::{Codes, QoS};
    /// use mqute_codec::protocol::v4::ReturnCode;
    ///
    /// let values = vec![ReturnCode::Failure, ReturnCode::Success(QoS::AtLeastOnce)];
    /// let codes: Codes<ReturnCode> = Codes::new(values);
    /// assert_eq!(codes.len(), 2);
    /// ```
    pub fn len(&self) -> usize {
        self.0.len()
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

impl<T> From<Codes<T>> for Vec<T> {
    #[inline]
    fn from(value: Codes<T>) -> Self {
        value.0
    }
}

impl<T> From<Vec<T>> for Codes<T> {
    #[inline]
    fn from(value: Vec<T>) -> Self {
        Codes(value)
    }
}

/// The `TopicFilters` provides a structure to handle a collection of MQTT topic filters.
/// Topic filters are used in MQTT subscriptions and unsubscriptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicFilters(Vec<String>);

#[allow(clippy::len_without_is_empty)]
impl TopicFilters {
    /// Creates a new `TopicFilters` instance from an iterator of topic filters.
    ///
    /// # Panics
    ///
    /// Panics if the iterator is empty, as at least one topic filter is required.
    ///
    /// # Example
    ///
    /// ```rust
    /// use mqute_codec::protocol::TopicFilters;
    ///
    /// let filters = TopicFilters::new(vec!["topic1", "topic2"]);
    /// ```
    pub fn new<T: IntoIterator<Item: Into<String>>>(filters: T) -> Self {
        let values: Vec<String> = filters.into_iter().map(|x| x.into()).collect();

        if values.is_empty() {
            panic!("At least one topic filter is required");
        }

        TopicFilters(values)
    }

    /// Returns the number of topic filters in the `TopicFilters` instance.
    /// ```rust
    /// use mqute_codec::protocol::TopicFilters;
    ///
    /// let filters = TopicFilters::new(vec!["topic1", "topic2"]);
    /// assert_eq!(filters.len(), 2);
    /// ```
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Decodes a `TopicFilters` instance from a byte buffer.
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

    /// Encodes the `TopicFilters` instance into a byte buffer.
    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        self.0.iter().for_each(|filter| {
            encode_string(buf, filter);
        });
    }

    /// Calculates the encoded length of the `TopicFilters` instance.
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

impl From<TopicFilters> for Vec<String> {
    #[inline]
    fn from(value: TopicFilters) -> Self {
        value.0
    }
}

impl From<Vec<String>> for TopicFilters {
    #[inline]
    fn from(value: Vec<String>) -> Self {
        TopicFilters(value)
    }
}

impl<T> Index<usize> for Codes<T> {
    type Output = T;
    fn index(&self, index: usize) -> &Self::Output {
        self.0.index(index)
    }
}

impl<T> IndexMut<usize> for Codes<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.0.index_mut(index)
    }
}
