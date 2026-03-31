//! [Mumble] protocol implementation in Rust.
//!
//! [Mumble]: https://mumble.info/

//#![deny(missing_docs)] //Makes missing documentation an actual error.
#![warn(clippy::all)]

pub use voice::Clientbound;
pub use voice::Serverbound;

pub mod control;
#[cfg(feature = "openssl")]
pub mod crypt;
pub mod ping;
pub mod varint;
pub mod voice;

#[cfg(not(any(feature = "asynchronous-codec", feature = "tokio-codec")))]
compile_error!("need at least one of asynchronous-codec or tokio-codec features to compile");
