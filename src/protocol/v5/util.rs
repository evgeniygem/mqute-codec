macro_rules! ack_properties {
    ($name:ident) => {
        #[derive(Debug, Default, Clone, PartialEq, Eq)]
        pub struct $name {
            /// Human-readable reason string
            pub reason_string: Option<String>,
            /// User-defined key-value properties
            pub user_properties: Vec<(String, String)>,
        }
    };
}

macro_rules! ack_properties_frame_impl {
    ($name:ident) => {
        impl $crate::protocol::v5::property::PropertyFrame for $name {
            fn encoded_len(&self) -> usize {
                let mut len = 0usize;

                len += $crate::protocol::v5::property::property_len!(&self.reason_string);
                len += $crate::protocol::v5::property::property_len!(&self.user_properties);

                len
            }

            fn encode(&self, buf: &mut bytes::BytesMut) {
                $crate::protocol::v5::property::property_encode!(
                    &self.reason_string,
                    $crate::protocol::v5::property::Property::ReasonString,
                    buf
                );
                $crate::protocol::v5::property::property_encode!(
                    &self.user_properties,
                    $crate::protocol::v5::property::Property::UserProperty,
                    buf
                );
            }

            fn decode(buf: &mut bytes::Bytes) -> Result<Option<Self>, $crate::Error>
            where
                Self: Sized,
            {
                use bytes::Buf;

                if buf.is_empty() {
                    return Ok(None);
                }

                let mut reason_string: Option<String> = None;
                let mut user_properties: Vec<(String, String)> = Vec::new();

                while buf.has_remaining() {
                    let property: $crate::protocol::v5::property::Property =
                        $crate::codec::util::decode_byte(buf)?.try_into()?;
                    match property {
                        $crate::protocol::v5::property::Property::ReasonString => {
                            $crate::protocol::v5::property::property_decode!(
                                &mut reason_string,
                                buf
                            );
                        }
                        $crate::protocol::v5::property::Property::UserProperty => {
                            $crate::protocol::v5::property::property_decode!(
                                &mut user_properties,
                                buf
                            );
                        }
                        _ => return Err($crate::Error::PropertyMismatch),
                    }
                }

                Ok(Some($name {
                    reason_string,
                    user_properties,
                }))
            }
        }
    };
}

macro_rules! ack {
    ($name:ident, $properties:ident, $check:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub(crate) struct Header {
            packet_id: u16,
            code: $crate::protocol::v5::reason::ReasonCode,
            properties: Option<$properties>,
        }

        impl Header {
            pub(crate) fn new(
                packet_id: u16,
                code: $crate::protocol::v5::reason::ReasonCode,
                properties: Option<$properties>,
            ) -> Self {
                if packet_id == 0 {
                    panic!("Packet id is zero");
                }

                if !$check(code) {
                    panic!("Invalid reason code {code}");
                }

                Header {
                    packet_id,
                    code,
                    properties,
                }
            }

            pub(crate) fn encoded_len(&self) -> usize {
                use $crate::protocol::v5::property::PropertyFrame;

                // The reason code and property length can be omitted
                // if the reason code is 'Success' and there are no properties
                if self.properties.is_none()
                    && self.code == $crate::protocol::v5::reason::ReasonCode::Success
                {
                    return 2;
                }

                let properties_len = self
                    .properties
                    .as_ref()
                    .map(|properties| properties.encoded_len())
                    .unwrap_or(0);

                2 + 1 + $crate::protocol::util::len_bytes(properties_len) + properties_len
            }

            pub(crate) fn encode(&self, buf: &mut bytes::BytesMut) -> Result<(), $crate::Error> {
                use bytes::BufMut;
                use $crate::protocol::v5::property::PropertyFrame;

                buf.put_u16(self.packet_id);

                // The reason code and property length can be omitted
                // if the reason code is 'Success' and there are no properties
                if self.properties.is_none()
                    && self.code == $crate::protocol::v5::reason::ReasonCode::Success
                {
                    return Ok(());
                }

                buf.put_u8(self.code.into());

                let properties_len = self
                    .properties
                    .as_ref()
                    .map(|properties| properties.encoded_len())
                    .unwrap_or(0) as u32;

                // Encode properties len
                $crate::codec::util::encode_variable_integer(buf, properties_len)?;

                // Encode properties
                if let Some(properties) = self.properties.as_ref() {
                    properties.encode(buf);
                }

                Ok(())
            }

            pub(crate) fn decode(payload: &mut bytes::Bytes) -> Result<Self, $crate::Error> {
                use bytes::Buf;
                use $crate::protocol::v5::property::PropertyFrame;

                let packet_id = $crate::codec::util::decode_word(payload)?;

                if payload.is_empty() {
                    return Ok(Header {
                        packet_id,
                        code: $crate::protocol::v5::reason::ReasonCode::Success,
                        properties: None,
                    });
                }

                let code = $crate::codec::util::decode_byte(payload)?.try_into()?;

                if !$check(code) {
                    return Err($crate::Error::InvalidReasonCode(code.into()));
                }

                let properties_len =
                    $crate::codec::util::decode_variable_integer(&payload)? as usize;
                if payload.len()
                    < properties_len + $crate::protocol::util::len_bytes(properties_len)
                {
                    return Err($crate::Error::MalformedPacket);
                }

                // Skip properties len
                payload.advance($crate::protocol::util::len_bytes(properties_len));

                let mut frame = payload.split_to(properties_len);
                let properties = $properties::decode(&mut frame)?;

                Ok(Header {
                    packet_id,
                    code,
                    properties,
                })
            }
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            header: Header,
        }

        impl $name {
            pub fn new(packet_id: u16, code: ReasonCode, properties: Option<$properties>) -> Self {
                $name {
                    header: Header::new(packet_id, code, properties),
                }
            }

            pub fn packet_id(&self) -> u16 {
                self.header.packet_id
            }

            pub fn code(&self) -> $crate::protocol::v5::reason::ReasonCode {
                self.header.code
            }

            pub fn properties(&self) -> Option<$properties> {
                self.header.properties.clone()
            }
        }
    };
}

macro_rules! ack_encode_impl {
    ($name:ident, $packet_type:expr, $flags:expr) => {
        impl $crate::codec::Encode for $name {
            fn encode(&self, buf: &mut bytes::BytesMut) -> Result<(), $crate::Error> {
                let header = $crate::protocol::FixedHeader::with_flags(
                    $packet_type,
                    $flags,
                    self.payload_len(),
                );
                header.encode(buf)?;

                self.header.encode(buf)
            }

            fn payload_len(&self) -> usize {
                self.header.encoded_len()
            }
        }
    };
}

macro_rules! ack_decode_impl {
    ($name:ident, $packet_type:expr, $flags:expr, $check:ident) => {
        impl $crate::codec::Decode for $name {
            fn decode(mut packet: $crate::codec::RawPacket) -> Result<Self, $crate::Error> {
                if packet.header.packet_type() != $packet_type || packet.header.flags() != $flags {
                    return Err($crate::Error::MalformedPacket);
                }

                let header = Header::decode(&mut packet.payload)?;
                Ok($name { header })
            }
        }
    };
}

macro_rules! ping_packet_decode_impl {
    ($packet:ident, $packet_type:expr) => {
        impl $crate::codec::Decode for $packet {
            fn decode(packet: $crate::codec::RawPacket) -> Result<Self, $crate::Error> {
                if packet.header.packet_type() == $packet_type && packet.header.flags().is_default()
                {
                    Ok($packet {})
                } else {
                    Err($crate::Error::MalformedPacket)
                }
            }
        }
    };
}

macro_rules! ping_packet_encode_impl {
    ($packet:ident, $packet_type:expr) => {
        impl $crate::codec::Encode for $packet {
            fn encode(&self, buf: &mut bytes::BytesMut) -> Result<(), $crate::Error> {
                let header = $crate::protocol::FixedHeader::new($packet_type, 0);
                header.encode(buf)
            }

            fn payload_len(&self) -> usize {
                // No payload
                0
            }
        }
    };
}

macro_rules! id_header {
    ($name:ident, $properties:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        struct $name {
            packet_id: u16,
            properties: Option<$properties>,
        }

        impl $name {
            pub(crate) fn new(packet_id: u16, properties: Option<$properties>) -> Self {
                $name {
                    packet_id,
                    properties,
                }
            }

            pub(crate) fn encoded_len(&self) -> usize {
                use $crate::protocol::v5::property::PropertyFrame;

                let properties_len = self
                    .properties
                    .as_ref()
                    .map(|properties| properties.encoded_len())
                    .unwrap_or(0);

                2 + $crate::protocol::util::len_bytes(properties_len) + properties_len
            }

            pub(crate) fn encode(&self, buf: &mut bytes::BytesMut) -> Result<(), $crate::Error> {
                use bytes::BufMut;
                use $crate::protocol::v5::property::PropertyFrame;

                buf.put_u16(self.packet_id);

                let properties_len = self
                    .properties
                    .as_ref()
                    .map(|properties| properties.encoded_len())
                    .unwrap_or(0) as u32;

                // Encode properties len
                $crate::codec::util::encode_variable_integer(buf, properties_len)?;

                // Encode properties
                if let Some(properties) = self.properties.as_ref() {
                    properties.encode(buf);
                }

                Ok(())
            }

            pub(crate) fn decode(payload: &mut Bytes) -> Result<Self, $crate::Error> {
                use $crate::protocol::v5::property::PropertyFrame;

                let packet_id = $crate::codec::util::decode_word(payload)?;

                let properties_len =
                    $crate::codec::util::decode_variable_integer(payload)? as usize;
                if payload.len()
                    < properties_len + $crate::protocol::util::len_bytes(properties_len)
                {
                    return Err($crate::Error::MalformedPacket);
                }

                // Skip variable byte
                payload.advance($crate::protocol::util::len_bytes(properties_len));

                let mut properties_buf = payload.split_to(properties_len);

                // Deserialize properties
                let properties = $properties::decode(&mut properties_buf)?;
                Ok($name {
                    packet_id,
                    properties,
                })
            }
        }
    };
}

pub(crate) use ack;
pub(crate) use ack_decode_impl;
pub(crate) use ack_encode_impl;
pub(crate) use ack_properties;
pub(crate) use ack_properties_frame_impl;
pub(crate) use id_header;
pub(crate) use ping_packet_decode_impl;
pub(crate) use ping_packet_encode_impl;
