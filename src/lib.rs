//! # MQTT Protocol Implementation in Rust
//!
//! mqute-codec crate provides an implementation of the MQTT protocol in Rust.
//! It includes modules for encoding, decoding, and handling MQTT packets.

pub mod codec;
mod error;
pub mod protocol;

pub use error::Error;
