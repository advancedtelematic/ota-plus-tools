#![recursion_limit = "1024"]

extern crate chrono;
extern crate curve25519_dalek;
extern crate data_encoding;
extern crate derp;
extern crate env_logger;
#[macro_use]
extern crate error_chain;
extern crate itoa;
extern crate reqwest;
extern crate ring;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[cfg(not(test))]
extern crate serde_json as json;
#[cfg(test)]
extern crate serde_json as json;
extern crate tempfile;
extern crate toml;
extern crate untrusted;
extern crate uuid;

pub mod cache;
pub mod config;
pub mod crypto;
pub mod error;
pub mod http;
pub mod interchange;
mod shims;
pub mod tuf;
