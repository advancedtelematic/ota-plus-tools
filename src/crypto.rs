use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use std::str::FromStr;

use error::{Error, ErrorKind, Result};

pub enum KeyType {
    Ed25519,
}

impl ToString for KeyType {
    fn to_string(&self) -> String {
        match *self {
            KeyType::Ed25519 => "ed25519".into(),
        }
    }
}

impl FromStr for KeyType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "ed25519" => Ok(KeyType::Ed25519),
            _ => {
                bail!(ErrorKind::IllegalArgument(
                    format!("Unknown key type: {}", s),
                ))
            }
        }
    }
}

enum KeyPairInner {
    Ed25519(Ed25519KeyPair),
}

pub struct KeyPair {
    inner: KeyPairInner,
}

impl KeyPair {
    /// Outputs the raw bytes of the private key.
    pub fn new_key_bytes(typ: &KeyType) -> Result<Vec<u8>> {
        match *typ {
            KeyType::Ed25519 => {
                Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                    .map(|a| a.to_vec())
                    .map_err(|_| {
                        ErrorKind::Crypto("Failed to generate Ed25519 key".into()).into()
                    })
            }
        }
    }
}

/// Wrapper type for public key bytes.
pub struct PublicKey(Vec<u8>);
