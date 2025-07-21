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
/// The `Credentials` struct encapsulates the username and optional password used for authenticating
/// a client with an MQTT broker. It provides methods for creating, encoding, decoding, and
/// manipulating authentication data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    /// The username for authentication.
    username: String,

    /// An optional password for authentication
    password: Option<String>,
}

impl Credentials {
    /// Creates a new `Credentials` instance.
    ///
    /// # Arguments
    ///
    /// - `username`: The username for authentication. This can be any type that implements `Into<String>`.
    /// - `password`: An optional password for authentication.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mqute_codec::protocol::Credentials;
    ///
    /// let credentials = Credentials::new("user", Some("pass".to_string()));
    /// assert_eq!(credentials.username(), "user");
    /// assert_eq!(credentials.password(), Some("pass".to_string()));
    /// ```
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
    ///
    /// # Arguments
    ///
    /// - `username`: The username for authentication. This can be any type that implements `Into<String>`.
    ///
    /// # Returns
    ///
    /// A new `Credentials` instance with no password.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mqute_codec::protocol::Credentials;
    ///
    /// let credentials = Credentials::with_name("user");
    /// assert_eq!(credentials.username(), "user");
    /// assert_eq!(credentials.password(), None);
    /// ```
    pub fn with_name<T: Into<String>>(username: T) -> Self {
        Self::new(username, None)
    }

    /// Creates a new `Credentials` instance with both a username and password.
    ///
    /// # Arguments
    ///
    /// - `username`: The username for authentication. This can be any type that implements `Into<String>`.
    /// - `password`: The password for authentication. This can be any type that implements `Into<String>`.
    ///
    /// # Returns
    ///
    /// A new `Credentials` instance with both username and password.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mqute_codec::protocol::Credentials;
    ///
    /// let credentials = Credentials::login("user", "pass");
    /// assert_eq!(credentials.username(), "user");
    /// assert_eq!(credentials.password(), Some("pass".to_string()));
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
    /// use mqute_codec::protocol::Credentials;
    ///
    /// let credentials = Credentials::with_name("user");
    /// assert_eq!(credentials.username(), "user");
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
    /// use mqute_codec::protocol::Credentials;
    ///
    /// let credentials = Credentials::login("user", "pass");
    /// assert_eq!(credentials.password(), Some("pass".to_string()));
    /// ```
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
        /// Represents an MQTT Connect packet
        ///
        /// This packet initiates a connection between client and broker and contains
        /// all necessary parameters for the session.
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
                keep_alive: u16,
                clean_session: bool,
            ) -> Self {
                use bit_field::BitField;
                use $crate::protocol::common::WillFrame;

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
            /// # Examples
            ///
            /// ```
            /// use mqute_codec::protocol::v5::Connect;
            ///
            /// // Simple publisher connection
            /// let publisher = Connect::new(
            ///     "pub-client",
            ///     None,
            ///     None,
            ///     0,  // Disable keep alive
            ///     true
            /// );
            pub fn new<S: Into<String>>(
                client_id: S,
                credentials: Option<$crate::protocol::Credentials>,
                will: Option<$will>,
                keep_alive: u16,
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
            ///
            /// # Example
            /// ```
            /// use mqute_codec::protocol::{v5::Connect, Protocol};
            ///
            /// let connect = Connect::new("client", None, None, 10, true);
            /// assert_eq!(connect.protocol(), Protocol::V5);
            /// ```
            pub fn protocol(&self) -> $crate::protocol::Protocol {
                self.header.protocol
            }

            /// Returns the keep alive time in seconds
            ///
            /// # Example
            /// ```
            /// use mqute_codec::protocol::v5::Connect;
            ///
            /// let connect = Connect::new("client", None, None, 45, true);
            /// assert_eq!(connect.keep_alive(), 45);
            /// ```
            pub fn keep_alive(&self) -> u16 {
                self.header.keep_alive
            }

            /// Returns whether this is a clean session
            ///
            /// # Example
            /// ```
            /// use mqute_codec::protocol::v5::Connect;
            ///
            /// let clean = Connect::new("client", None, None, 10, true);
            /// assert!(clean.clean_session());
            /// ```
            pub fn clean_session(&self) -> bool {
                use bit_field::BitField;
                self.header.flags.get_bit(CLEAN_SESSION)
            }

            /// Returns the client identifier
            ///
            /// # Example
            /// ```
            /// use mqute_codec::protocol::v5::Connect;
            ///
            /// let connect = Connect::new("my-device-01", None, None, 10, true);
            /// assert_eq!(connect.client_id(), "my-device-01");
            /// ```
            pub fn client_id(&self) -> String {
                self.payload.client_id.clone()
            }

            /// Returns the authentication credentials if present
            ///
            /// # Example
            /// ```
            /// use mqute_codec::protocol::{v5::Connect, Credentials};
            ///
            /// let secure = Connect::new(
            ///     "client",
            ///     Some(Credentials::login("user", "pass")),
            ///     None,
            ///     10,
            ///     true
            /// );
            /// assert!(secure.credentials().is_some());
            ///
            /// let anonymous = Connect::new("client", None, None, 10, true);
            /// assert!(anonymous.credentials().is_none());
            /// ```
            pub fn credentials(&self) -> Option<$crate::protocol::common::Credentials> {
                self.payload.credentials.clone()
            }

            /// Returns the will message if present
            ///
            /// # Example
            /// ```
            /// use bytes::Bytes;
            /// use mqute_codec::protocol::{v5::Connect, v5::Will, QoS};
            ///
            /// let with_will = Connect::new(
            ///     "client",
            ///     None,
            ///     Some(Will::new(
            ///         None,
            ///         "device/status",
            ///         Bytes::from("disconnected"),
            ///         QoS::ExactlyOnce,
            ///         true
            ///     )),
            ///     10,
            ///     true
            /// );
            /// assert!(with_will.will().is_some());
            /// ```
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
