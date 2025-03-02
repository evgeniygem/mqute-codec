use crate::codec::util::{
    decode_byte, decode_bytes, decode_dword, decode_string, decode_variable_integer, decode_word,
    encode_bytes, encode_string, encode_variable_integer,
};
use crate::protocol::util::len_bytes;
use crate::{Error, QoS};
use bytes::{BufMut, Bytes, BytesMut};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Property {
    PayloadFormatIndicator,
    MessageExpiryInterval,
    ContentType,
    ResponseTopic,
    CorrelationData,
    SubscriptionIdentifier,
    SessionExpiryInterval,
    AssignedClientIdentifier,
    ServerKeepAlive,
    AuthenticationMethod,
    AuthenticationData,
    RequestProblemInformation,
    WillDelayInterval,
    RequestResponseInformation,
    ResponseInformation,
    ServerReference,
    ReasonString,
    ReceiveMaximum,
    TopicAliasMaximum,
    TopicAlias,
    MaximumQoS,
    RetainAvailable,
    UserProperty,
    MaximumPacketSize,
    WildcardSubscriptionAvailable,
    SubscriptionIdentifierAvailable,
    SharedSubscriptionAvailable,
}

impl Into<u8> for Property {
    fn into(self) -> u8 {
        match self {
            Self::PayloadFormatIndicator => 1,
            Self::MessageExpiryInterval => 2,
            Self::ContentType => 3,
            Self::ResponseTopic => 8,
            Self::CorrelationData => 9,
            Self::SubscriptionIdentifier => 11,
            Self::SessionExpiryInterval => 17,
            Self::AssignedClientIdentifier => 18,
            Self::ServerKeepAlive => 19,
            Self::AuthenticationMethod => 21,
            Self::AuthenticationData => 22,
            Self::RequestProblemInformation => 23,
            Self::WillDelayInterval => 24,
            Self::RequestResponseInformation => 25,
            Self::ResponseInformation => 26,
            Self::ServerReference => 28,
            Self::ReasonString => 31,
            Self::ReceiveMaximum => 33,
            Self::TopicAliasMaximum => 34,
            Self::TopicAlias => 35,
            Self::MaximumQoS => 36,
            Self::RetainAvailable => 37,
            Self::UserProperty => 38,
            Self::MaximumPacketSize => 39,
            Self::WildcardSubscriptionAvailable => 40,
            Self::SubscriptionIdentifierAvailable => 41,
            Self::SharedSubscriptionAvailable => 42,
        }
    }
}

impl TryFrom<u8> for Property {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let property = match value {
            1 => Self::PayloadFormatIndicator,
            2 => Self::MessageExpiryInterval,
            3 => Self::ContentType,
            8 => Self::ResponseTopic,
            9 => Self::CorrelationData,
            11 => Self::SubscriptionIdentifier,
            17 => Self::SessionExpiryInterval,
            18 => Self::AssignedClientIdentifier,
            19 => Self::ServerKeepAlive,
            21 => Self::AuthenticationMethod,
            22 => Self::AuthenticationData,
            23 => Self::RequestProblemInformation,
            24 => Self::WillDelayInterval,
            25 => Self::RequestResponseInformation,
            26 => Self::ResponseInformation,
            28 => Self::ServerReference,
            31 => Self::ReasonString,
            33 => Self::ReceiveMaximum,
            34 => Self::TopicAliasMaximum,
            35 => Self::TopicAlias,
            36 => Self::MaximumQoS,
            37 => Self::RetainAvailable,
            38 => Self::UserProperty,
            39 => Self::MaximumPacketSize,
            40 => Self::WildcardSubscriptionAvailable,
            41 => Self::SubscriptionIdentifierAvailable,
            42 => Self::SharedSubscriptionAvailable,
            n => return Err(Error::InvalidProperty(n)),
        };

        Ok(property)
    }
}

pub(crate) trait PropertyFrame {
    fn encoded_len(&self) -> usize;
    fn encode(&self, buf: &mut BytesMut);
    fn decode(buf: &mut Bytes) -> Result<Option<Self>, Error>
    where
        Self: Sized;
}

pub(super) trait PropertyValue {
    fn property_len(value: &Self) -> usize;
    fn encode(value: &Self, property: Property, buf: &mut BytesMut);
    fn decode(value: &mut Self, buf: &mut Bytes) -> Result<(), Error>;
}

impl PropertyValue for Option<bool> {
    #[inline]
    fn property_len(value: &Self) -> usize {
        match value {
            None => 0,
            Some(_) => 1 + 1,
        }
    }

    fn encode(value: &Self, property: Property, buf: &mut BytesMut) {
        match value {
            None => {}
            Some(value) => {
                buf.put_u8(property.into());
                buf.put_u8(*value as u8);
            }
        }
    }

    fn decode(value: &mut Self, buf: &mut Bytes) -> Result<(), Error> {
        if value.is_some() {
            return Err(Error::ProtocolError);
        }

        let byte = decode_byte(buf)?;
        if byte != 0 || byte != 1 {
            return Err(Error::ProtocolError);
        }

        *value = Some(byte != 0);
        Ok(())
    }
}

impl PropertyValue for Option<u8> {
    #[inline]
    fn property_len(value: &Self) -> usize {
        match value {
            None => 0,
            Some(_) => 1 + 1,
        }
    }

    fn encode(value: &Self, property: Property, buf: &mut BytesMut) {
        match value {
            None => {}
            Some(value) => {
                buf.put_u8(property.into());
                buf.put_u8(*value);
            }
        }
    }

    fn decode(value: &mut Self, buf: &mut Bytes) -> Result<(), Error> {
        if value.is_some() {
            return Err(Error::ProtocolError);
        }

        *value = Some(decode_byte(buf)?);
        Ok(())
    }
}

impl PropertyValue for Option<QoS> {
    #[inline]
    fn property_len(value: &Self) -> usize {
        match value {
            None => 0,
            Some(_) => 1 + 1,
        }
    }

    fn encode(value: &Self, property: Property, buf: &mut BytesMut) {
        match value {
            None => {}
            Some(value) => {
                buf.put_u8(property.into());
                buf.put_u8((*value).into());
            }
        }
    }

    fn decode(value: &mut Self, buf: &mut Bytes) -> Result<(), Error> {
        if value.is_some() {
            return Err(Error::ProtocolError);
        }

        let byte = decode_byte(buf)?;
        if byte != 0 || byte != 1 {
            return Err(Error::ProtocolError);
        }

        *value = Some(QoS::try_from(byte)?);
        Ok(())
    }
}

impl PropertyValue for Option<u16> {
    #[inline]
    fn property_len(value: &Self) -> usize {
        match value {
            None => 0,
            Some(_) => 1 + 2,
        }
    }

    fn encode(value: &Self, property: Property, buf: &mut BytesMut) {
        match value {
            None => {}
            Some(value) => {
                buf.put_u8(property.into());
                buf.put_u16(*value);
            }
        }
    }

    fn decode(value: &mut Self, buf: &mut Bytes) -> Result<(), Error> {
        if value.is_some() {
            return Err(Error::ProtocolError);
        }

        *value = Some(decode_word(buf)?);
        Ok(())
    }
}

impl PropertyValue for Option<u32> {
    #[inline]
    fn property_len(value: &Self) -> usize {
        match value {
            None => 0,
            Some(_) => 1 + 4,
        }
    }

    fn encode(value: &Self, property: Property, buf: &mut BytesMut) {
        match value {
            None => {}
            Some(value) => {
                buf.put_u8(property.into());
                buf.put_u32(*value);
            }
        }
    }

    fn decode(value: &mut Self, buf: &mut Bytes) -> Result<(), Error> {
        if value.is_some() {
            return Err(Error::ProtocolError);
        }

        *value = Some(decode_dword(buf)?);
        Ok(())
    }
}

impl PropertyValue for Option<String> {
    #[inline]
    fn property_len(value: &Self) -> usize {
        match value {
            None => 0,
            Some(value) => 1 + 2 + value.len(),
        }
    }

    fn encode(value: &Self, property: Property, buf: &mut BytesMut) {
        match value {
            None => {}
            Some(value) => {
                buf.put_u8(property.into());
                encode_string(buf, value);
            }
        }
    }

    fn decode(value: &mut Self, buf: &mut Bytes) -> Result<(), Error> {
        if value.is_some() {
            return Err(Error::ProtocolError);
        }

        *value = Some(decode_string(buf)?);
        Ok(())
    }
}

impl PropertyValue for Vec<(String, String)> {
    #[inline]
    fn property_len(value: &Self) -> usize {
        value.iter().fold(0, |acc, (key, value)| {
            acc + 1 + 2 + key.len() + 2 + value.len()
        })
    }

    fn encode(value: &Self, property: Property, buf: &mut BytesMut) {
        value.iter().for_each(|(key, value)| {
            buf.put_u8(property.into());
            encode_string(buf, key);
            encode_string(buf, value);
        });
    }

    fn decode(value: &mut Self, buf: &mut Bytes) -> Result<(), Error> {
        let key = decode_string(buf)?;
        let val = decode_string(buf)?;
        value.push((key, val));
        Ok(())
    }
}

impl PropertyValue for Option<Bytes> {
    #[inline]
    fn property_len(value: &Self) -> usize {
        match value {
            None => 0,
            Some(value) => 1 + 2 + value.len(),
        }
    }

    fn encode(value: &Self, property: Property, buf: &mut BytesMut) {
        match value {
            None => {}
            Some(value) => {
                buf.put_u8(property.into());
                encode_bytes(buf, value);
            }
        }
    }

    fn decode(value: &mut Self, buf: &mut Bytes) -> Result<(), Error> {
        if value.is_some() {
            return Err(Error::ProtocolError);
        }

        *value = Some(decode_bytes(buf)?);
        Ok(())
    }
}

impl PropertyValue for Vec<u32> {
    #[inline]
    fn property_len(value: &Self) -> usize {
        value
            .iter()
            .fold(0, |acc, &value| acc + 1 + len_bytes(value as usize))
    }

    fn encode(value: &Self, property: Property, buf: &mut BytesMut) {
        value.iter().for_each(|&len| {
            buf.put_u8(property.into());
            encode_variable_integer(buf, len).expect("Value is too big for encode");
        });
    }

    fn decode(value: &mut Self, buf: &mut Bytes) -> Result<(), Error> {
        let len = decode_variable_integer(buf)? as u32;
        value.push(len);
        Ok(())
    }
}

macro_rules! property_len {
    ($e:expr) => {
        $crate::protocol::v5::property::PropertyValue::property_len($e)
    };
}

macro_rules! property_encode {
    ($e:expr, $property_id:expr, $buf:expr) => {
        $crate::protocol::v5::property::PropertyValue::encode($e, $property_id, $buf);
    };
}

macro_rules! property_decode {
    ($e:expr, $buf:expr) => {
        $crate::protocol::v5::property::PropertyValue::decode($e, $buf)?;
    };
}

macro_rules! property_decode_non_zero {
    ($e:expr, $buf:expr) => {
        property_decode!($e, $buf);
        if let Some(&value) = $e.as_ref() {
            if value == 0 {
                return Err($crate::Error::ProtocolError);
            }
        }
    };
}

pub(crate) use property_decode;
pub(crate) use property_decode_non_zero;
pub(crate) use property_encode;
pub(crate) use property_len;
