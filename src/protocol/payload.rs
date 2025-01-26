use crate::codec::util::{decode_byte, decode_bytes, decode_string, encode_bytes, encode_string};
use crate::Error;
use crate::QoS;
use bit_field::BitField;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::borrow::Borrow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    pub username: String,
    pub password: Option<String>,
}

impl Auth {
    pub fn new<T>(username: T, password: Option<String>) -> Self
    where
        T: Into<String>,
    {
        Auth {
            username: username.into(),
            password,
        }
    }

    pub fn with_name<T: Into<String>>(username: T) -> Self {
        Self::new(username, None)
    }

    pub fn login<T: Into<String>, U: Into<String>>(username: T, password: U) -> Self {
        Self::new(username.into(), Some(password.into()))
    }

    pub(crate) fn encoded_len(&self) -> usize {
        let mut size = 2 + self.username.len();
        if let Some(password) = self.password.as_ref() {
            size += 2 + password.len();
        }
        size
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        encode_string(buf, &self.username);

        if let Some(password) = self.password.as_ref() {
            encode_string(buf, password);
        }
    }

    pub(crate) fn update_flags(&self, flags: &mut u8) {
        // Update username flag
        flags.set_bit(Flag::Username as usize, true);

        // Update password flag
        flags.set_bit(Flag::Password as usize, self.password.is_some());
    }

    pub(crate) fn decode(buf: &mut Bytes, flags: u8) -> Result<Option<Self>, Error> {
        if !flags.get_bit(Flag::Username as usize) {
            return Ok(None);
        }

        let username = decode_string(buf)?;

        let password = if flags.get_bit(Flag::Password as usize) {
            Some(decode_string(buf)?)
        } else {
            None
        };

        Ok(Some(Auth::new(username, password)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Will {
    topic: String,
    message: Bytes,
    qos: QoS,
    retain: bool,
}

impl Will {
    pub fn new<T: Into<String>>(topic: T, message: Bytes, qos: QoS, retain: bool) -> Self {
        Will {
            topic: topic.into(),
            message,
            qos,
            retain,
        }
    }

    pub(crate) fn encoded_len(&self) -> usize {
        2 + self.topic.len() + 2 + self.message.len()
    }

    pub(crate) fn update_flags(&self, flags: &mut u8) {
        // Update the 'Will' flag
        flags.set_bit(Flag::WillFlag as usize, true);
        let qos_range = (Flag::WillQosBegin as usize)..=(Flag::WillQosEnd as usize);

        // Update 'Qos' flags
        flags.set_bits(qos_range, self.qos as u8);

        // Update the 'Will Retain' flag
        flags.set_bit(Flag::WillRetain as usize, self.retain);
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        encode_string(buf, &self.topic);
        encode_bytes(buf, &self.message);
    }

    pub(crate) fn decode(buf: &mut Bytes, flags: u8) -> Result<Option<Self>, Error> {
        if !flags.get_bit(Flag::WillFlag as usize) {
            // No 'Will'
            return Ok(None);
        }

        let qos_range = (Flag::WillQosBegin as usize)..=(Flag::WillQosEnd as usize);
        let qos = flags.get_bits(qos_range).try_into()?;

        let retain = flags.get_bit(Flag::WillRetain as usize);

        let topic = decode_string(buf)?;
        let message = decode_bytes(buf)?;
        Ok(Some(Will::new(topic, message, qos, retain)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectPayload {
    pub client_id: String,
    pub auth: Option<Auth>,
    pub will: Option<Will>,
}

impl ConnectPayload {
    pub fn new<T: Into<String>>(client_id: T, auth: Option<Auth>, will: Option<Will>) -> Self {
        ConnectPayload {
            client_id: client_id.into(),
            auth,
            will,
        }
    }

    pub fn decode(payload: &mut Bytes, flags: u8) -> Result<Self, Error> {
        let client_id = decode_string(payload)?;

        let will = Will::decode(payload, flags)?;
        let auth = Auth::decode(payload, flags)?;

        Ok(ConnectPayload {
            client_id,
            auth,
            will,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        // Encode the client id
        encode_string(buf, &self.client_id);

        if let Some(will) = self.will.as_ref() {
            will.encode(buf);
        }

        if let Some(auth) = self.auth.as_ref() {
            auth.encode(buf);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Flag {
    WillFlag = 2,
    WillQosBegin = 3,
    WillQosEnd = 4,
    WillRetain = 5,
    Password = 6,
    Username = 7,
}

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

    pub(crate) fn decode(payload: &mut Bytes, size: usize) -> Result<Self, Error> {
        let mut codes: Vec<T> = Vec::with_capacity(size);
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
pub struct TopicQosFilter {
    pub topic: String,
    pub qos: QoS,
}

impl TopicQosFilter {
    pub fn new<T: Into<String>>(topic: T, qos: QoS) -> Self {
        Self {
            topic: topic.into(),
            qos,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicQosFilters(Vec<TopicQosFilter>);

impl TopicQosFilters {
    pub fn new<T: IntoIterator<Item = TopicQosFilter>>(filters: T) -> Self {
        let values: Vec<TopicQosFilter> = filters.into_iter().collect();

        if values.is_empty() {
            panic!("At least one topic filter is required");
        }

        TopicQosFilters(values)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn decode(payload: &mut Bytes) -> Result<Self, Error> {
        let mut filters = Vec::with_capacity(1);

        while payload.has_remaining() {
            let filter = decode_string(payload)?;
            let flags = decode_byte(payload)?;

            // The upper 6 bits of the Requested QoS byte must be zero
            if flags & 0b1111_1100 > 0 {
                return Err(Error::MalformedPacket);
            }

            filters.push(TopicQosFilter::new(filter, flags.try_into()?));
        }

        if filters.is_empty() {
            return Err(Error::NoTopic);
        }

        Ok(TopicQosFilters(filters))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        self.0.iter().for_each(|f| {
            encode_string(buf, &f.topic);
            buf.put_u8(f.qos.into());
        });
    }

    pub(crate) fn encoded_len(&self) -> usize {
        self.0.iter().fold(0, |acc, f| acc + 2 + f.topic.len() + 1)
    }
}

impl AsRef<Vec<TopicQosFilter>> for TopicQosFilters {
    #[inline]
    fn as_ref(&self) -> &Vec<TopicQosFilter> {
        self.0.as_ref()
    }
}

impl Borrow<Vec<TopicQosFilter>> for TopicQosFilters {
    fn borrow(&self) -> &Vec<TopicQosFilter> {
        self.0.as_ref()
    }
}

impl IntoIterator for TopicQosFilters {
    type Item = TopicQosFilter;
    type IntoIter = std::vec::IntoIter<TopicQosFilter>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl FromIterator<TopicQosFilter> for TopicQosFilters {
    fn from_iter<T: IntoIterator<Item = TopicQosFilter>>(iter: T) -> Self {
        TopicQosFilters(Vec::from_iter(iter))
    }
}

impl Into<Vec<TopicQosFilter>> for TopicQosFilters {
    #[inline]
    fn into(self) -> Vec<TopicQosFilter> {
        self.0
    }
}

impl From<Vec<TopicQosFilter>> for TopicQosFilters {
    #[inline]
    fn from(value: Vec<TopicQosFilter>) -> Self {
        TopicQosFilters(value)
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
