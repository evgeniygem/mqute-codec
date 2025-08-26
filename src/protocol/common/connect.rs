//! # Connect Packet
//!
//! This module provides structures and utilities for handling the MQTT Connect packet,
//! which is used to initiate a connection between a client and an MQTT broker.

use crate::Error;
use crate::codec::util::{decode_byte, decode_string, decode_word, encode_string};
use crate::protocol::Protocol;
use crate::protocol::common::frame::WillFrame;
use bit_field::BitField;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::time::Duration;

/// Represents the header of the MQTT Connect packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectHeader<T> {
    pub protocol: Protocol,
    pub flags: u8,
    pub keep_alive: Duration,
    pub properties: Option<T>,
}

impl<T> ConnectHeader<T> {
    /// Creates a new `ConnectHeader`.
    pub(crate) fn new(
        protocol: Protocol,
        flags: u8,
        keep_alive: Duration,
        properties: Option<T>,
    ) -> Self {
        ConnectHeader {
            protocol,
            flags,
            keep_alive,
            properties,
        }
    }

    /// Calculates the length of the primary encoded header.
    ///
    /// This includes the protocol name, protocol level, flags, and keep-alive duration.
    pub(crate) fn primary_encoded_len(&self) -> usize {
        2 + self.protocol.name().len() // Protocol name string
            + 1                        // Protocol level
            + 1                        // Connect flags
            + 2 // Keep alive
    }

    /// Encodes the primary header fields into the provided buffer.
    pub(crate) fn primary_encode(&self, buf: &mut BytesMut) {
        // Encode the protocol name
        encode_string(buf, self.protocol.name());

        // Add the protocol level
        buf.put_u8(self.protocol.into());

        // Add the flags
        buf.put_u8(self.flags);

        // Add the keep alive timeout
        buf.put_u16(self.keep_alive.as_secs() as u16);
    }

    /// Decodes the primary header fields from the provided buffer.
    pub(crate) fn primary_decode(buf: &mut Bytes) -> Result<Self, Error> {
        let protocol_name = decode_string(buf)?;

        let protocol: Protocol = buf.get_u8().try_into()?;

        if protocol_name != protocol.name() {
            return Err(Error::InvalidProtocolName(protocol_name));
        }

        let flags = decode_byte(buf)?;
        let keep_alive = decode_word(buf)?;

        Ok(ConnectHeader {
            protocol,
            flags,
            keep_alive: Duration::from_secs(keep_alive as u64),
            properties: None,
        })
    }
}

const PASSWORD: usize = 6;
const USERNAME: usize = 7;

/// Represents authentication information for an MQTT connection.
///
/// The `Credentials` struct encapsulates the username and optional password used for authenticating
/// a client with an MQTT broker. It provides methods for creating, encoding, decoding, and
/// manipulating authentication data.
///
/// # Examples
///
/// ```rust
/// use mqute_codec::protocol::Credentials;
///
/// let credentials = Credentials::full("user", "pass");
/// assert_eq!(credentials.username(), "user");
/// assert_eq!(credentials.password(), Some("pass".to_string()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    /// The username for authentication.
    username: String,

    /// An optional password for authentication
    password: Option<String>,
}

impl Credentials {
    /// Creates a new `Credentials` instance.
    pub fn new<T>(username: T, password: Option<String>) -> Self
    where
        T: Into<String>,
    {
        Credentials {
            username: username.into(),
            password,
        }
    }

    /// Creates a new `Credentials` instance with only a username.
    pub fn with_name<T: Into<String>>(username: T) -> Self {
        Self::new(username, None)
    }

    /// Creates a new `Credentials` instance with both a username and password.
    pub fn full<T: Into<String>, U: Into<String>>(username: T, password: U) -> Self {
        Self::new(username.into(), Some(password.into()))
    }

    /// Returns the username.
    pub fn username(&self) -> String {
        self.username.clone()
    }

    /// Returns the optional password.
    pub fn password(&self) -> Option<String> {
        self.password.clone()
    }

    /// Calculates the encoded length of the `Credentials` structure.
    ///
    /// This is used to determine the size of the buffer required to encode the `Credentials` data.
    pub(crate) fn encoded_len(&self) -> usize {
        let mut size = 2 + self.username.len(); // 2 bytes for string length + username length
        if let Some(password) = self.password.as_ref() {
            size += 2 + password.len(); // 2 bytes for string length + password length
        }
        size
    }

    /// Encodes the `Credentials` structure into the provided buffer.
    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        encode_string(buf, &self.username);

        if let Some(password) = self.password.as_ref() {
            encode_string(buf, password);
        }
    }

    /// Updates the connection flags based on the presence of a username and password.
    pub(crate) fn update_flags(&self, flags: &mut u8) {
        // Update username flag
        flags.set_bit(USERNAME, true);

        // Update password flag
        flags.set_bit(PASSWORD, self.password.is_some());
    }

    /// Decodes the `Credentials` structure from the provided buffer and flags.
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

        Ok(Some(Credentials::new(username, password)))
    }
}

/// Represents the payload of the MQTT Connect packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectPayload<T> {
    pub client_id: String,
    pub credentials: Option<Credentials>,
    pub will: Option<T>,
}

impl<T> ConnectPayload<T>
where
    T: WillFrame,
{
    /// Creates a new `ConnectPayload`.
    pub(crate) fn new<S: Into<String>>(
        client_id: S,
        credentials: Option<Credentials>,
        will: Option<T>,
    ) -> Self {
        ConnectPayload {
            client_id: client_id.into(),
            credentials,
            will,
        }
    }

    /// Decodes the `ConnectPayload` from the provided buffer and flags.
    pub(crate) fn decode(payload: &mut Bytes, flags: u8) -> Result<Self, Error> {
        let client_id = decode_string(payload)?;

        let will = T::decode(payload, flags)?;
        let credentials = Credentials::decode(payload, flags)?;

        Ok(ConnectPayload {
            client_id,
            credentials,
            will,
        })
    }

    /// Encodes the `ConnectPayload` into the provided buffer.
    pub(crate) fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        // Encode the client id
        encode_string(buf, &self.client_id);

        if let Some(will) = self.will.as_ref() {
            will.encode(buf)?;
        }

        if let Some(credentials) = self.credentials.as_ref() {
            credentials.encode(buf);
        }

        Ok(())
    }

    /// Calculates the encoded length of the `ConnectPayload`.
    pub(crate) fn encoded_len(&self) -> usize {
        2 + self.client_id.len() +            // Client ID
            self.will                         // WillFlag
                .as_ref()
                .map(|will| will.encoded_len())
                .unwrap_or(0) +
            self.credentials                         // Credentials
                .as_ref()
                .map(|credentials| credentials.encoded_len())
                .unwrap_or(0)
    }
}

/// Generates a Connect packet structure with specific properties and will message types.
///
/// The `connect!` macro is used to generate a Connect packet structure that includes
/// the header, payload, and encoding/decoding logic for a specific MQTT protocol version.
macro_rules! connect {
    ($name:ident <$property:ident, $will:ident>, $proto:expr) => {
        /// Represents an MQTT `Connect` packet
        ///
        /// This packet initiates a connection between client and broker and contains
        /// all necessary parameters for the session.
        ///
        /// # Example
        ///
        /// ```rust
        /// use std::time::Duration;
        /// use bytes::Bytes;
        /// use mqute_codec::protocol::{v5, Credentials, Protocol, QoS};
        ///
        /// let connect = v5::Connect::new(
        ///     "client",
        ///     Some(Credentials::full("user", "pass")),
        ///     Some(v5::Will::new(
        ///         None,
        ///         "device/status",
        ///         Bytes::from("disconnected"),
        ///         QoS::ExactlyOnce,
        ///         true
        ///     )),
        ///     Duration::from_secs(30),
        ///     true
        /// );
        /// assert!(connect.will().is_some());
        /// assert_eq!(connect.protocol(), Protocol::V5);
        /// assert_eq!(connect.client_id(), "client");
        /// ```
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            header: $crate::protocol::common::ConnectHeader<$property>,
            payload: $crate::protocol::common::ConnectPayload<$will>,
        }

        const CLEAN_SESSION: usize = 1;

        impl $name {
            fn from_scratch<S: Into<String>>(
                client_id: S,
                credentials: Option<$crate::protocol::common::Credentials>,
                will: Option<$will>,
                properties: Option<$property>,
                keep_alive: std::time::Duration,
                clean_session: bool,
            ) -> Self {
                use bit_field::BitField;
                use $crate::protocol::common::WillFrame;

                if (keep_alive.as_secs() > u16::MAX as u64) {
                    panic!("Invalid 'keep alive' value");
                }

                let mut flags = 0u8;

                flags.set_bit(CLEAN_SESSION, clean_session);

                if let Some(credentials) = credentials.as_ref() {
                    credentials.update_flags(&mut flags);
                }

                if let Some(will) = will.as_ref() {
                    will.update_flags(&mut flags);
                }

                let header = $crate::protocol::common::ConnectHeader::<$property>::new(
                    $proto, flags, keep_alive, properties,
                );
                let payload = $crate::protocol::common::ConnectPayload::<$will>::new(
                    client_id,
                    credentials,
                    will,
                );

                Self { header, payload }
            }

            /// Creates a new Connect packet with basic parameters
            ///
            /// # Panics
            ///
            /// Panics if the value of the "keep alive" parameter exceeds 65535
            pub fn new<S: Into<String>>(
                client_id: S,
                credentials: Option<$crate::protocol::Credentials>,
                will: Option<$will>,
                keep_alive: std::time::Duration,
                clean_session: bool,
            ) -> Self {
                Self::from_scratch(
                    client_id,
                    credentials,
                    will,
                    None,
                    keep_alive,
                    clean_session,
                )
            }

            /// Returns the protocol version being used
            pub fn protocol(&self) -> $crate::protocol::Protocol {
                self.header.protocol
            }

            /// Returns the keep alive time in seconds
            pub fn keep_alive(&self) -> std::time::Duration {
                self.header.keep_alive
            }

            /// Returns whether this is a clean session
            pub fn clean_session(&self) -> bool {
                use bit_field::BitField;
                self.header.flags.get_bit(CLEAN_SESSION)
            }

            /// Returns the client identifier
            pub fn client_id(&self) -> String {
                self.payload.client_id.clone()
            }

            /// Returns the authentication credentials if present
            pub fn credentials(&self) -> Option<$crate::protocol::common::Credentials> {
                self.payload.credentials.clone()
            }

            /// Returns the will message if present
            pub fn will(&self) -> Option<$will> {
                self.payload.will.clone()
            }
        }

        impl $crate::codec::Encode for $name {
            fn encode(&self, buf: &mut bytes::BytesMut) -> Result<(), $crate::Error> {
                use $crate::protocol::common::ConnectFrame;

                let header = $crate::protocol::FixedHeader::new(
                    $crate::protocol::PacketType::Connect,
                    self.payload_len(),
                );

                // Encode fixed header
                header.encode(buf)?;

                // Encode variable header
                self.header.encode(buf)?;

                // Encode payload
                self.payload.encode(buf)
            }

            fn payload_len(&self) -> usize {
                use $crate::protocol::common::ConnectFrame;
                self.header.encoded_len() + self.payload.encoded_len()
            }
        }

        impl $crate::codec::Decode for $name {
            fn decode(mut packet: $crate::codec::RawPacket) -> Result<Self, $crate::Error> {
                use $crate::protocol::common::ConnectFrame;

                if packet.header.packet_type() != $crate::protocol::PacketType::Connect
                    || !packet.header.flags().is_default()
                {
                    return Err($crate::Error::MalformedPacket);
                }

                let header = $crate::protocol::common::ConnectHeader::<$property>::decode(
                    &mut packet.payload,
                )?;

                if header.protocol != $proto {
                    return Err($crate::Error::ProtocolNotSupported);
                }
                let payload = $crate::protocol::common::ConnectPayload::<$will>::decode(
                    &mut packet.payload,
                    header.flags,
                )?;

                Ok(Self { header, payload })
            }
        }

        impl $crate::protocol::traits::Connect for $name {}
    };
}

pub(crate) use connect;
