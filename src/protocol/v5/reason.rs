//! # MQTT Reason Codes V5
//!
//! This module defines the `ReasonCode` enum, which represents all possible reason codes
//! used in MQTT v5 protocol packets. Reason codes provide detailed information about
//! the result of operations or the cause of disconnections.

use crate::Error;
use std::fmt::{Display, Formatter};

/// Represents all possible reason codes in MQTT v5 protocol.
///
/// Reason codes are used in various MQTT packets to indicate the result of operations
/// or the reason for disconnections. Each variant corresponds to a specific numeric code
/// as defined in the MQTT v5 specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    /// Success (0x00)
    Success,
    /// Normal disconnection (0x00)
    NormalDisconnection,
    /// Granted QoS 0 (0x00)
    GrantedQos0,
    /// Granted QoS 1 (0x01)
    GrantedQos1,
    /// Granted QoS 2 (0x02)
    GrantedQos2,
    /// Disconnect with Will Message (0x04)
    DisconnectWithWillMessage,
    /// No matching subscribers (0x10)
    NoMatchingSubscribers,
    /// No subscription existed (0x11)
    NoSubscriptionExisted,
    /// Continue authentication (0x18)
    ContinueAuthentication,
    /// Re-authenticate (0x19)
    ReAuthenticate,
    /// Unspecified error (0x80)
    UnspecifiedError,
    /// Malformed Packet (0x81)
    MalformedPacket,
    /// Protocol Error (0x82)
    ProtocolError,
    /// Implementation specific error (0x83)
    ImplementationSpecificError,
    /// Unsupported Protocol Version (0x84)
    UnsupportedProtocolVersion,
    /// Client Identifier not valid (0x85)
    ClientIdentifierNotValid,
    /// Bad User Name or Password (0x86)
    BadUserNameOrPassword,
    /// Not authorized (0x87)
    NotAuthorized,
    /// Server unavailable (0x88)
    ServerUnavailable,
    /// Server busy (0x89)
    ServerBusy,
    /// Banned (0x8A)
    Banned,
    /// Server shutting down (0x8B)
    ServerShuttingDown,
    /// Bad authentication method (0x8C)
    BadAuthenticationMethod,
    /// Keep Alive timeout (0x8D)
    KeepAliveTimeout,
    /// Session taken over (0x8E)
    SessionTakenOver,
    /// Topic Filter invalid (0x8F)
    TopicFilterInvalid,
    /// Topic Name invalid (0x90)
    TopicNameInvalid,
    /// Packet Identifier in use (0x91)
    PacketIdentifierInUse,
    /// Packet Identifier not found (0x92)
    PacketIdentifierNotFound,
    /// Receive Maximum exceeded (0x93)
    ReceiveMaximumExceeded,
    /// Topic Alias invalid (0x94)
    TopicAliasInvalid,
    /// Packet too large (0x95)
    PacketTooLarge,
    /// Message rate too high (0x96)
    MessageRateTooHigh,
    /// Quota exceeded (0x97)
    QuotaExceeded,
    /// Administrative action (0x98)
    AdministrativeAction,
    /// Payload format invalid (0x99)
    PayloadFormatInvalid,
    /// Retain not supported (0x9A)
    RetainNotSupported,
    /// QoS not supported (0x9B)
    QosNotSupported,
    /// Use another server (0x9C)
    UseAnotherServer,
    /// Server moved (0x9D)
    ServerMoved,
    /// Shared Subscriptions not supported (0x9E)
    SharedSubscriptionsNotSupported,
    /// Connection rate exceeded (0x9F)
    ConnectionRateExceeded,
    /// Maximum connect time (0xA0)
    MaximumConnectTime,
    /// Subscription Identifiers not supported (0xA1)
    SubscriptionIdentifiersNotSupported,
    /// Wildcard Subscriptions not supported (0xA2)
    WildcardSubscriptionsNotSupported,
}

impl From<ReasonCode> for u8 {
    /// Converts a `ReasonCode` to its numeric representation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use mqute_codec::protocol::v5::ReasonCode;
    ///
    /// let code: u8 = ReasonCode::GrantedQos1.into();
    /// assert_eq!(code, 1);
    /// ```
    fn from(value: ReasonCode) -> Self {
        match value {
            ReasonCode::Success => 0,
            ReasonCode::NormalDisconnection => 0,
            ReasonCode::GrantedQos0 => 0,
            ReasonCode::GrantedQos1 => 1,
            ReasonCode::GrantedQos2 => 2,
            ReasonCode::DisconnectWithWillMessage => 4,
            ReasonCode::NoMatchingSubscribers => 16,
            ReasonCode::NoSubscriptionExisted => 17,
            ReasonCode::ContinueAuthentication => 24,
            ReasonCode::ReAuthenticate => 25,
            ReasonCode::UnspecifiedError => 128,
            ReasonCode::MalformedPacket => 129,
            ReasonCode::ProtocolError => 130,
            ReasonCode::ImplementationSpecificError => 131,
            ReasonCode::UnsupportedProtocolVersion => 132,
            ReasonCode::ClientIdentifierNotValid => 133,
            ReasonCode::BadUserNameOrPassword => 134,
            ReasonCode::NotAuthorized => 135,
            ReasonCode::ServerUnavailable => 136,
            ReasonCode::ServerBusy => 137,
            ReasonCode::Banned => 138,
            ReasonCode::ServerShuttingDown => 139,
            ReasonCode::BadAuthenticationMethod => 140,
            ReasonCode::KeepAliveTimeout => 141,
            ReasonCode::SessionTakenOver => 142,
            ReasonCode::TopicFilterInvalid => 143,
            ReasonCode::TopicNameInvalid => 144,
            ReasonCode::PacketIdentifierInUse => 145,
            ReasonCode::PacketIdentifierNotFound => 146,
            ReasonCode::ReceiveMaximumExceeded => 147,
            ReasonCode::TopicAliasInvalid => 148,
            ReasonCode::PacketTooLarge => 149,
            ReasonCode::MessageRateTooHigh => 150,
            ReasonCode::QuotaExceeded => 151,
            ReasonCode::AdministrativeAction => 152,
            ReasonCode::PayloadFormatInvalid => 153,
            ReasonCode::RetainNotSupported => 154,
            ReasonCode::QosNotSupported => 155,
            ReasonCode::UseAnotherServer => 156,
            ReasonCode::ServerMoved => 157,
            ReasonCode::SharedSubscriptionsNotSupported => 158,
            ReasonCode::ConnectionRateExceeded => 159,
            ReasonCode::MaximumConnectTime => 160,
            ReasonCode::SubscriptionIdentifiersNotSupported => 161,
            ReasonCode::WildcardSubscriptionsNotSupported => 162,
        }
    }
}

impl TryFrom<u8> for ReasonCode {
    type Error = Error;

    /// Attempts to convert a numeric value to a `ReasonCode`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use mqute_codec::protocol::v5::ReasonCode;
    ///
    /// let code = ReasonCode::try_from(0x85).unwrap();
    /// assert_eq!(code, ReasonCode::ClientIdentifierNotValid);
    /// ```
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let code = match value {
            0 => Self::Success,
            1 => Self::GrantedQos1,
            2 => Self::GrantedQos2,
            4 => Self::DisconnectWithWillMessage,
            16 => Self::NoMatchingSubscribers,
            17 => Self::NoSubscriptionExisted,
            24 => Self::ContinueAuthentication,
            25 => Self::ReAuthenticate,
            128 => Self::UnspecifiedError,
            129 => Self::MalformedPacket,
            130 => Self::ProtocolError,
            131 => Self::ImplementationSpecificError,
            132 => Self::UnsupportedProtocolVersion,
            133 => Self::ClientIdentifierNotValid,
            134 => Self::BadUserNameOrPassword,
            135 => Self::NotAuthorized,
            136 => Self::ServerUnavailable,
            137 => Self::ServerBusy,
            138 => Self::Banned,
            139 => Self::ServerShuttingDown,
            140 => Self::BadAuthenticationMethod,
            141 => Self::KeepAliveTimeout,
            142 => Self::SessionTakenOver,
            143 => Self::TopicFilterInvalid,
            144 => Self::TopicNameInvalid,
            145 => Self::PacketIdentifierInUse,
            146 => Self::PacketIdentifierNotFound,
            147 => Self::ReceiveMaximumExceeded,
            148 => Self::TopicAliasInvalid,
            149 => Self::PacketTooLarge,
            150 => Self::MessageRateTooHigh,
            151 => Self::QuotaExceeded,
            152 => Self::AdministrativeAction,
            153 => Self::PayloadFormatInvalid,
            154 => Self::RetainNotSupported,
            155 => Self::QosNotSupported,
            156 => Self::UseAnotherServer,
            157 => Self::ServerMoved,
            158 => Self::SharedSubscriptionsNotSupported,
            159 => Self::ConnectionRateExceeded,
            160 => Self::MaximumConnectTime,
            161 => Self::SubscriptionIdentifiersNotSupported,
            162 => Self::WildcardSubscriptionsNotSupported,
            n => return Err(Error::InvalidReasonCode(n)),
        };

        Ok(code)
    }
}

impl Display for ReasonCode {
    /// Provides human-readable display for reason codes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use mqute_codec::protocol::v5::ReasonCode;
    /// let str = format!("{}", ReasonCode::ProtocolError);
    /// let text = "Protocol Error".to_string();
    /// assert_eq!(text, str);
    /// ```
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            ReasonCode::Success => write!(f, "Success"),
            ReasonCode::NormalDisconnection => write!(f, "Normal disconnection"),
            ReasonCode::GrantedQos0 => write!(f, "Granted QoS 0"),
            ReasonCode::GrantedQos1 => write!(f, "Granted QoS 1"),
            ReasonCode::GrantedQos2 => write!(f, "Granted QoS 2"),
            ReasonCode::DisconnectWithWillMessage => write!(f, "Disconnect with Will Message"),
            ReasonCode::NoMatchingSubscribers => write!(f, "No matching subscribers"),
            ReasonCode::NoSubscriptionExisted => write!(f, "No subscription existed"),
            ReasonCode::ContinueAuthentication => write!(f, "Continue authentication"),
            ReasonCode::ReAuthenticate => write!(f, "Re authenticate"),
            ReasonCode::UnspecifiedError => write!(f, "Unspecified error"),
            ReasonCode::MalformedPacket => write!(f, "Malformed Packet"),
            ReasonCode::ProtocolError => write!(f, "Protocol Error"),
            ReasonCode::ImplementationSpecificError => write!(f, "Implementation specific error"),
            ReasonCode::UnsupportedProtocolVersion => write!(f, "Unsupported Protocol Version"),
            ReasonCode::ClientIdentifierNotValid => write!(f, "Client Identifier not valid"),
            ReasonCode::BadUserNameOrPassword => write!(f, "Bad User Name or Password"),
            ReasonCode::NotAuthorized => write!(f, "Not authorized"),
            ReasonCode::ServerUnavailable => write!(f, "Server unavailable"),
            ReasonCode::ServerBusy => write!(f, "Server busy"),
            ReasonCode::Banned => write!(f, "Banned"),
            ReasonCode::ServerShuttingDown => write!(f, "Server shutting down"),
            ReasonCode::BadAuthenticationMethod => write!(f, "Bad authentication method"),
            ReasonCode::KeepAliveTimeout => write!(f, "Keep Alive timeout"),
            ReasonCode::SessionTakenOver => write!(f, "Session taken over"),
            ReasonCode::TopicFilterInvalid => write!(f, "Topic Filter invalid"),
            ReasonCode::TopicNameInvalid => write!(f, "Topic Name invalid"),
            ReasonCode::PacketIdentifierInUse => write!(f, "Packet Identifier in use"),
            ReasonCode::PacketIdentifierNotFound => write!(f, "Packet Identifier not found"),
            ReasonCode::ReceiveMaximumExceeded => write!(f, "Receive Maximum exceeded"),
            ReasonCode::TopicAliasInvalid => write!(f, "Topic Alias invalid"),
            ReasonCode::PacketTooLarge => write!(f, "Packet too large"),
            ReasonCode::MessageRateTooHigh => write!(f, "Message rate too high"),
            ReasonCode::QuotaExceeded => write!(f, "Quota exceeded"),
            ReasonCode::AdministrativeAction => write!(f, "Administrative action"),
            ReasonCode::PayloadFormatInvalid => write!(f, "Payload format invalid"),
            ReasonCode::RetainNotSupported => write!(f, "Retain not supported"),
            ReasonCode::QosNotSupported => write!(f, "QoS not supported"),
            ReasonCode::UseAnotherServer => write!(f, "Use another server"),
            ReasonCode::ServerMoved => write!(f, "Server moved"),
            ReasonCode::SharedSubscriptionsNotSupported => {
                write!(f, "Shared Subscriptions not supported")
            }
            ReasonCode::ConnectionRateExceeded => write!(f, "Connection rate exceeded"),
            ReasonCode::MaximumConnectTime => write!(f, "Maximum connect time"),
            ReasonCode::SubscriptionIdentifiersNotSupported => {
                write!(f, "Subscription Identifiers not supported")
            }
            ReasonCode::WildcardSubscriptionsNotSupported => {
                write!(f, "Wildcard Subscriptions not supported")
            }
        }
    }
}
