/// Generates a SubAck packet structure with specific code types.
///
/// The `suback!` macro is used to generate a `SubAck` packet structure that includes
/// the payload, and encoding/decoding logic for a specific MQTT protocol version (only V4 and V3).
macro_rules! suback {
    ($code:ty) => {
        use bytes::BufMut;

        /// The `SubAck` packet is sent by the server to the client to confirm receipt and
        /// processing of a subscription request. It contains return codes indicating the
        /// maximum QoS level granted for each requested subscription.
        ///
        /// # Examples
        ///
        /// ```rust
        /// use mqute_codec::protocol::QoS;
        /// use mqute_codec::protocol::v4::{ReturnCode, SubAck};
        ///
        /// // Single subscription
        /// let suback = SubAck::new(1, vec![ReturnCode::Success(QoS::AtMostOnce)]);
        ///
        /// let codes = suback.codes();
        /// assert_eq!(codes[0], ReturnCode::Success(QoS::AtMostOnce));
        /// ```
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct SubAck {
            packet_id: u16,
            codes: $crate::protocol::Codes<$code>,
        }

        impl SubAck {
            /// Creates a new `SubAck` packet
            ///
            /// # Panics
            ///
            /// Panics if packet_id is 0 (invalid packet identifier)
            pub fn new<I: IntoIterator<Item = $code>>(packet_id: u16, codes: I) -> Self {
                if packet_id == 0 {
                    panic!("Packet id is zero");
                }

                let codes = $crate::protocol::Codes::new(codes);

                SubAck { packet_id, codes }
            }

            /// Returns the subscription return codes
            ///
            /// Each code indicates the result of the corresponding subscription request:
            /// - Success variants contain the granted QoS level
            /// - Failure indicates the subscription was not accepted
            pub fn codes(&self) -> $crate::protocol::Codes<$code> {
                self.codes.clone()
            }

            /// Returns the packet identifier
            ///
            /// This matches the identifier from the corresponding `Subscribe` packet
            pub fn packet_id(&self) -> u16 {
                self.packet_id
            }
        }
        impl $crate::codec::Decode for SubAck {
            fn decode(mut packet: $crate::codec::RawPacket) -> Result<Self, $crate::Error> {
                if packet.header.packet_type() != $crate::protocol::PacketType::SubAck
                    || !packet.header.flags().is_default()
                {
                    return Err($crate::Error::MalformedPacket);
                }

                let packet_id = $crate::codec::util::decode_word(&mut packet.payload)?;

                // 'remaining len' is always at least 2
                let codes = $crate::protocol::Codes::decode(&mut packet.payload)?;

                Ok(SubAck { packet_id, codes })
            }
        }

        impl $crate::codec::Encode for SubAck {
            fn encode(&self, buf: &mut bytes::BytesMut) -> Result<(), $crate::Error> {
                let header = $crate::protocol::FixedHeader::new(
                    $crate::protocol::PacketType::SubAck,
                    self.payload_len(),
                );
                header.encode(buf)?;

                buf.put_u16(self.packet_id);
                self.codes.encode(buf);
                Ok(())
            }

            fn payload_len(&self) -> usize {
                2 + self.codes.len()
            }
        }
    };
}

pub(crate) use suback;
