use crate::codec::util::{decode_string, encode_string};
use crate::protocol::common::frame::WillFrame;
use crate::Error;
use bit_field::BitField;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::borrow::Borrow;

const PASSWORD: usize = 6;
const USERNAME: usize = 7;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    username: String,
    password: Option<String>,
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

    pub fn username(&self) -> String {
        self.username.clone()
    }

    pub fn password(&self) -> Option<String> {
        self.password.clone()
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
        flags.set_bit(USERNAME, true);

        // Update password flag
        flags.set_bit(PASSWORD, self.password.is_some());
    }

    pub(crate) fn decode(buf: &mut Bytes, flags: u8) -> Result<Option<Self>, Error> {
        if !flags.get_bit(USERNAME) {
            return Ok(None);
        }

        let username = decode_string(buf)?;

        let password = if flags.get_bit(PASSWORD) {
            Some(decode_string(buf)?)
        } else {
            None
        };

        Ok(Some(Auth::new(username, password)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectPayload<T> {
    pub client_id: String,
    pub auth: Option<Auth>,
    pub will: Option<T>,
}

impl<T> ConnectPayload<T>
where
    T: WillFrame,
{
    pub(crate) fn new<S: Into<String>>(client_id: S, auth: Option<Auth>, will: Option<T>) -> Self {
        ConnectPayload {
            client_id: client_id.into(),
            auth,
            will,
        }
    }

    pub(crate) fn decode(payload: &mut Bytes, flags: u8) -> Result<Self, Error> {
        let client_id = decode_string(payload)?;

        let will = T::decode(payload, flags)?;
        let auth = Auth::decode(payload, flags)?;

        Ok(ConnectPayload {
            client_id,
            auth,
            will,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        // Encode the client id
        encode_string(buf, &self.client_id);

        if let Some(will) = self.will.as_ref() {
            will.encode(buf)?;
        }

        if let Some(auth) = self.auth.as_ref() {
            auth.encode(buf);
        }

        Ok(())
    }

    pub(crate) fn encoded_len(&self) -> usize {
        2 + self.client_id.len() +            // Client ID
            self.will                         // WillFlag
                .as_ref()
                .map(|will| will.encoded_len())
                .unwrap_or(0) +
            self.auth                         // Auth
                .as_ref()
                .map(|auth| auth.encoded_len())
                .unwrap_or(0)
    }
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
