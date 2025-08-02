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

### Encoding and Decoding a Connect Packet

```rust
use mqute_codec::protocol::{Credentials, QoS};
use mqute_codec::protocol::v5::{Connect, Packet, Will};
use std::time::Duration;
use bytes::{Bytes, BytesMut};
use mqute_codec::codec::{PacketCodec, Encode, Decode};
use tokio_util::codec::{Decoder, Encoder};

fn main() {
    let credentials = Credentials::login("user", "password");
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
        Duration::from_secs(30).as_secs() as u16,
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
            // Create a length-delimited codec
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
- Auth (v5 only)

## Documentation

Complete API documentation is available on [docs.rs](https://docs.rs/mqute-codec).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.