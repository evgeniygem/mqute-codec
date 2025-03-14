//! # Connect Packet
//!
//! This module provides structures and utilities for handling the MQTT Connect packet,
//! which is used to initiate a connection between a client and an MQTT broker.

use crate::codec::util::{decode_byte, decode_string, decode_word, encode_string};
use crate::protocol::common::frame::WillFrame;
use crate::protocol::Protocol;
use crate::Error;
use bit_field::BitField;
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Represents the header of the MQTT Connect packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectHeader<T> {
    pub protocol: Protocol,
    pub flags: u8,
    pub keep_alive: u16,
    pub properties: Option<T>,
}

impl<T> ConnectHeader<T> {
    /// Creates a new `ConnectHeader`.
    pub(crate) fn new(
        protocol: Protocol,
        flags: u8,
        keep_alive: u16,
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
        buf.put_u16(self.keep_alive);
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
            keep_alive,
            properties: None,
        })
    }
}

const PASSWORD: usize = 6;
const USERNAME: usize = 7;

/// Represents authentication information for an MQTT connection.
///
/// The `Auth` struct encapsulates the username and optional password used for authenticating
/// a client with an MQTT broker. It provides methods for creating, encoding, decoding, and
/// manipulating authentication data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    /// The username for authentication.
    username: String,

    /// An optional password for authentication
    password: Option<String>,
}

impl Auth {
    /// Creates a new `Auth` instance.
    ///
    /// # Arguments
    ///
    /// - `username`: The username for authentication. This can be any type that implements `Into<String>`.
    /// - `password`: An optional password for authentication.
    ///
    /// # Returns
    ///
    /// A new `Auth` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mqute_codec::protocol::Auth;
    ///
    /// let auth = Auth::new("user", Some("pass".to_string()));
    /// assert_eq!(auth.username(), "user");
    /// assert_eq!(auth.password(), Some("pass".to_string()));
    /// ```
    pub fn new<T>(username: T, password: Option<String>) -> Self
    where
        T: Into<String>,
    {
        Auth {
            username: username.into(),
            password,
        }
    }

    /// Creates a new `Auth` instance with only a username.
    ///
    /// # Arguments
    ///
    /// - `username`: The username for authentication. This can be any type that implements `Into<String>`.
    ///
    /// # Returns
    ///
    /// A new `Auth` instance with no password.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mqute_codec::protocol::Auth;
    ///
    /// let auth = Auth::with_name("user");
    /// assert_eq!(auth.username(), "user");
    /// assert_eq!(auth.password(), None);
    /// ```
    pub fn with_name<T: Into<String>>(username: T) -> Self {
        Self::new(username, None)
    }

    /// Creates a new `Auth` instance with both a username and password.
    ///
    /// # Arguments
    ///
    /// - `username`: The username for authentication. This can be any type that implements `Into<String>`.
    /// - `password`: The password for authentication. This can be any type that implements `Into<String>`.
    ///
    /// # Returns
    ///
    /// A new `Auth` instance with both username and password.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mqute_codec::protocol::Auth;
    ///
    /// let auth = Auth::login("user", "pass");
    /// assert_eq!(auth.username(), "user");
    /// assert_eq!(auth.password(), Some("pass".to_string()));
    /// ```
    pub fn login<T: Into<String>, U: Into<String>>(username: T, password: U) -> Self {
        Self::new(username.into(), Some(password.into()))
    }

    /// Returns the username.
    ///
    /// # Returns
    ///
    /// The username as a `String`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mqute_codec::protocol::Auth;
    ///
    /// let auth = Auth::with_name("user");
    /// assert_eq!(auth.username(), "user");
    /// ```
    pub fn username(&self) -> String {
        self.username.clone()
    }

    /// Returns the optional password.
    ///
    /// # Returns
    ///
    /// The password as an `Option<String>`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mqute_codec::protocol::Auth;
    ///
    /// let auth = Auth::login("user", "pass");
    /// assert_eq!(auth.password(), Some("pass".to_string()));
    /// ```
    pub fn password(&self) -> Option<String> {
        self.password.clone()
    }

    /// Calculates the encoded length of the `Auth` structure.
    ///
    /// This is used to determine the size of the buffer required to encode the `Auth` data.
    pub(crate) fn encoded_len(&self) -> usize {
        let mut size = 2 + self.username.len(); // 2 bytes for string length + username length
        if let Some(password) = self.password.as_ref() {
            size += 2 + password.len(); // 2 bytes for string length + password length
        }
        size
    }

    /// Encodes the `Auth` structure into the provided buffer.
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

    /// Decodes the `Auth` structure from the provided buffer and flags.
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

/// Represents the payload of the MQTT Connect packet.
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
    /// Creates a new `ConnectPayload`.
    pub(crate) fn new<S: Into<String>>(client_id: S, auth: Option<Auth>, will: Option<T>) -> Self {
        ConnectPayload {
            client_id: client_id.into(),
            auth,
            will,
        }
    }

    /// Decodes the `ConnectPayload` from the provided buffer and flags.
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

    /// Encodes the `ConnectPayload` into the provided buffer.
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

    /// Calculates the encoded length of the `ConnectPayload`.
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

/// Generates a Connect packet structure with specific properties and will message types.
///
/// The `connect!` macro is used to generate a Connect packet structure that includes
/// the header, payload, and encoding/decoding logic for a specific MQTT protocol version.
macro_rules! connect {
    ($name:ident <$property:ident, $will:ident>, $proto:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            header: $crate::protocol::common::ConnectHeader<$property>,
            payload: $crate::protocol::common::ConnectPayload<$will>,
        }

        const CLEAN_SESSION: usize = 1;

        impl $name {
            fn from_scratch<S: Into<String>>(
                client_id: S,
                auth: Option<$crate::protocol::common::Auth>,
                will: Option<$will>,
                properties: Option<$property>,
                keep_alive: u16,
                clean_session: bool,
            ) -> Self {
                use bit_field::BitField;
                use $crate::protocol::common::WillFrame;

                let mut flags = 0u8;

                flags.set_bit(CLEAN_SESSION, clean_session);

                if let Some(auth) = auth.as_ref() {
                    auth.update_flags(&mut flags);
                }

                if let Some(will) = will.as_ref() {
                    will.update_flags(&mut flags);
                }

                let header = $crate::protocol::common::ConnectHeader::<$property>::new(
                    $proto, flags, keep_alive, properties,
                );
                let payload =
                    $crate::protocol::common::ConnectPayload::<$will>::new(client_id, auth, will);

                Self { header, payload }
            }

            pub fn new<S: Into<String>>(
                client_id: S,
                auth: Option<$crate::protocol::Auth>,
                will: Option<$will>,
                keep_alive: u16,
                clean_session: bool,
            ) -> Self {
                Self::from_scratch(client_id, auth, will, None, keep_alive, clean_session)
            }

            pub fn protocol(&self) -> $crate::protocol::Protocol {
                self.header.protocol
            }

            pub fn keep_alive(&self) -> u16 {
                self.header.keep_alive
            }

            pub fn clean_session(&self) -> bool {
                use bit_field::BitField;
                self.header.flags.get_bit(CLEAN_SESSION)
            }

            pub fn client_id(&self) -> String {
                self.payload.client_id.clone()
            }

            pub fn auth(&self) -> Option<$crate::protocol::common::Auth> {
                self.payload.auth.clone()
            }

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
    };
}

pub(crate) use connect;
