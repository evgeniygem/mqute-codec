# mqute-codec - MQTT Packet Serialization Library

[![Crates.io](https://img.shields.io/crates/v/mqute-codec)](https://crates.io/crates/mqute-codec)
[![Documentation](https://docs.rs/mqute-codec/badge.svg)](https://docs.rs/mqute-codec)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A feature-complete, zero-allocation implementation of MQTT (Message Queuing Telemetry Transport) protocol serialization in Rust, supporting versions 3.1, 3.1.1, and 5.0 with strict protocol compliance and validation.

## Description

`mqute-codec` is a high-performance MQTT packet serialization/deserialization library designed for building robust MQTT clients, brokers, and protocol tools. It provides:

- **Complete Packet Handling**: Full support for all MQTT packet types across all protocol versions
- **Zero-Copy Parsing**: Maximum performance with minimal memory overhead
- **Protocol Compliance**: Strict validation of packet structure, fields, and protocol rules
- **Version Support**: MQTT 3.1, 3.1.1, and 5.0 with version-specific features
- **Async-Ready**: Designed for seamless integration with async runtimes

This library focuses exclusively on the packet layer, making it ideal for:

- Building custom MQTT clients and brokers
- Protocol analysis and diagnostic tools
- Embedded systems requiring minimal memory footprint
- Testing and benchmarking MQTT implementations
- Educational purposes for understanding MQTT protocol internals

## Features

### Core Features
- **Full Protocol Support**: MQTT 3.1, 3.1.1, and 5.0 packet formats
- **Zero-Copy Architecture**: Minimal allocations for maximum performance
- **Strict Validation**: Comprehensive protocol compliance checking
- **Flexible Error Handling**: Detailed error types with context information
- **Async Integration**: Ready for use with tokio and other async runtimes

### MQTT v5 Specific Features
- **Property Support**: Full implementation of MQTT v5 properties
- **Enhanced Authentication**: Auth packet and extended authentication flows
- **Reason Codes**: Detailed error and status reporting
- **User Properties**: Custom metadata support
- **Shared Subscriptions**: Load balancing and group messaging

### Performance Features
- **Zero Allocation Parsing**: For most common packet types
- **Buffer Reuse**: Efficient memory management
- **Batch Processing**: Optimized for high-throughput scenarios
- **Minimal Dependencies**: Lightweight dependency tree

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
mqute-codec = "0.4"
```

## Usage Examples

### Encoding and Decoding a Connect Packet

```rust
use mqute_codec::protocol::{Credentials, QoS};
use mqute_codec::protocol::v5::{Connect, Packet, Will};
use std::time::Duration;
use bytes::{Bytes, BytesMut};
use mqute_codec::codec::{PacketCodec, Encode, Decode};
use tokio_util::codec::{Decoder, Encoder};

fn main() {
    let credentials = Credentials::full("user", "password");
    let original = Packet::Connect(Connect::new(
        "client",
        Some(credentials),
        Some(Will::new(
            None,
            "device/status",
            Bytes::from("disconnected"),
            QoS::ExactlyOnce,
            true
        )),
        Duration::from_secs(30),
        true
    ));

    let mut codec = PacketCodec::new(Some(4096), Some(4096));
    let mut buf = BytesMut::new();
    original.encode(&mut buf).unwrap();

    let raw = codec.try_decode(&mut buf).unwrap();
    let restored = Packet::decode(raw).unwrap();

    assert_eq!(original, restored);
}
```

### Basic MQTT Server Implementation


```rust
use mqute_codec::protocol::v5::Packet;
use mqute_codec::codec::{PacketCodec, RawPacket};

use tokio::net::TcpListener;
use tokio_util::codec::Framed;
use futures::StreamExt;

async fn on_recv(raw: RawPacket) {
    if let Ok(packet) = Packet::decode(raw) {
        match packet {
            Packet::Connect(packet) => unimplemented!(),
            Packet::ConnAck(packet) => unimplemented!(),
            Packet::Publish(packet) => unimplemented!(),
            Packet::PubAck(packet) => unimplemented!(),
            Packet::PubRec(packet) => unimplemented!(),
            Packet::PubRel(packet) => unimplemented!(),
            Packet::PubComp(packet) => unimplemented!(),
            Packet::Subscribe(packet) => unimplemented!(),
            Packet::SubAck(packet) => unimplemented!(),
            Packet::Unsubscribe(packet) => unimplemented!(),
            Packet::UnsubAck(packet) => unimplemented!(),
            Packet::PingReq(packet) => unimplemented!(),
            Packet::PingResp(packet) => unimplemented!(),
            Packet::Disconnect(packet) => unimplemented!(),
            Packet::Auth(packet) => unimplemented!(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:1883").await?;

    loop {
        let (socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            let mut framed = Framed::new(socket, PacketCodec::new(Some(4096), None));

            while let Some(frame) = framed.next().await {
                match frame {
                    Ok(raw) => {
                        on_recv(raw).await;
                    }
                    Err(e) => {
                        eprintln!("Error processing frame: {}", e);
                        break;
                    }
                }
            }
        });
    }
}
```

## Supported MQTT Packets

- Connect/ConnAck
- Publish/PubAck/PubRec/PubRel/PubComp
- Subscribe/SubAck
- Unsubscribe/UnsubAck
- PingReq/PingResp
- Disconnect

## MQTT v5 Exclusive

- Auth - Enhanced authentication flows
- Property Support - Full property encoding/decoding
- Reason Codes - Detailed status reporting

## Performance Characteristics

- Zero Allocation: Most packet types parsed without heap allocations
- Memory Efficient: Minimal memory footprint

## Documentation

Complete API documentation is available on [docs.rs](https://docs.rs/mqute-codec).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.