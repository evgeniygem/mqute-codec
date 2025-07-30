# mqute-codec - MQTT Packet Serialization Library

[![Crates.io](https://img.shields.io/crates/v/mqute-codec)](https://crates.io/crates/mqute-codec)
[![Documentation](https://docs.rs/mqute-codec/badge.svg)](https://docs.rs/mqute-codec)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A feature-complete implementation of the MQTT (Message Queuing Telemetry Transport) protocol serialization in Rust,
supporting versions 3.1, 3.1.1 and 5.0.

## Description

`mqute-codec` is a zero-allocation MQTT packet serialization/deserialization library that provides:

- **Packet construction**: Build all MQTT packet types programmatically
- **Wire format handling**: Convert packets to/from their binary representation
- **Protocol compliance**: Strict validation of packet structure and fields
- **Version support**: MQTT 3.1, 3.1.1 and 5.0 packet formats

This is not a full MQTT client/broker implementation - it focuses exclusively on the packet layer, making it ideal for:

- Building custom MQTT clients/servers
- Protocol analysis tools
- Embedded systems requiring minimal overhead
- Testing and benchmarking implementations

## Features

- Full support for MQTT 3.1, 3.1.1 and 5.0
- Zero-copy parsing for maximum performance
- Strict protocol compliance validation
- Flexible error handling system
- Async-ready design

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
mqute-codec = "0.1"
```

## Usage Examples

### Encoding a Connect Packet

```rust
use mqute_codec::protocol::v5::{Connect, ReasonCode};
use bytes::BytesMut;

let connect = Connect::new("client_id", None, None, 30, true);
let mut buffer = BytesMut::new();
connect.encode( & mut buffer).unwrap();
```

### Decoding Packets

```rust
use mqute_codec::codec::{PacketCodec, Decode};
use bytes::BytesMut;

let mut codec = PacketCodec::new(Some(1024), Some(1024));
let mut buffer = BytesMut::from(& [0x10, 0x0C, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x05, 0x02, 0x00, 0x3C, 0x00, 0x00][..]);

match codec.decode( & mut buffer) {
Ok(packet) => println ! ("Received packet: {:?}", packet),
Err(e) => eprintln !("Decoding error: {}", e),
}
```

## Supported MQTT Packets

- Connect/ConnAck
- Publish/PubAck/PubRec/PubRel/PubComp
- Subscribe/SubAck
- Unsubscribe/UnsubAck
- PingReq/PingResp
- Disconnect
- Auth (v5 only)

## Documentation

Complete API documentation is available on [docs.rs](https://docs.rs/mqute-codec).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.