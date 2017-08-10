use data_encoding::BASE64;
use ring::digest::{self, SHA256, SHA512};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use serde::ser::{Serialize, Serializer};
use std::collections::HashMap;
use std::fmt::{self, Debug, Display};
use std::io::Read;
use std::str::FromStr;

use error::{Error, ErrorKind, Result};

/// Calculate the size and hash digest from a given `Read`.
pub fn calculate_hashes<R: Read>(
    mut read: R,
    hash_algs: &[HashAlgorithm],
) -> Result<(u64, HashMap<HashAlgorithm, HashValue>)> {
    if hash_algs.len() == 0 {
        bail!(ErrorKind::IllegalArgument(
            "Cannot provide empty set of hash algorithms".into(),
        ));
    }

    let mut size = 0;
    let mut hashes = HashMap::new();
    for alg in hash_algs {
        let context = match alg {
            &HashAlgorithm::Sha256 => digest::Context::new(&SHA256),
            &HashAlgorithm::Sha512 => digest::Context::new(&SHA512),
        };

        let _ = hashes.insert(alg, context);
    }

    let mut buf = vec![0; 1024];
    loop {
        match read.read(&mut buf) {
            Ok(read_bytes) => {
                if read_bytes == 0 {
                    break;
                }

                size += read_bytes as u64;

                for (_, mut context) in hashes.iter_mut() {
                    context.update(&buf[0..read_bytes]);
                }
            }
            e @ Err(_) => e.map(|_| ())?,
        }
    }

    let hashes = hashes
        .drain()
        .map(|(k, v)| {
            (k.clone(), HashValue::new(v.finish().as_ref().to_vec()))
        })
        .collect();
    Ok((size, hashes))
}

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

/// Wrapper type for the value of a cryptographic signature.
pub struct SignatureValue(Vec<u8>);

impl SignatureValue {
    /// Create a new `SignatureValue` from the given bytes.
    ///
    /// Note: It is unlikely that you ever want to do this manually.
    pub fn new(bytes: Vec<u8>) -> Self {
        SignatureValue(bytes)
    }

    /// Create a new `SignatureValue` from the given base64 string.
    ///
    /// Note: It is unlikely that you ever want to do this manually.
    pub fn from_string(string: &str) -> Result<Self> {
        Ok(SignatureValue(BASE64.decode(string.as_bytes())?))
    }
}

impl Debug for SignatureValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SignatureValue({})", BASE64.encode(&self.0))
    }
}

impl Serialize for SignatureValue {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        BASE64.encode(&self.0).serialize(ser)
    }
}

impl<'de> Deserialize<'de> for SignatureValue {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let string: String = Deserialize::deserialize(de)?;
        SignatureValue::from_string(&string).map_err(|e| {
            DeserializeError::custom(format!("Signature value was not valid base64: {:?}", e))
        })
    }
}

/// Cryptographic signature schemes.
#[derive(Debug, Serialize, Deserialize)]
pub enum SignatureScheme {
    /// [Ed25519](https://ed25519.cr.yp.to/)
    #[serde(rename = "ed25519")]
    Ed25519,
    /// [RSASSA-PSS](https://tools.ietf.org/html/rfc5756) calculated over SHA256
    #[serde(rename = "rsassa-pss-sha256")]
    RsaSsaPssSha256,
    /// [RSASSA-PSS](https://tools.ietf.org/html/rfc5756) calculated over SHA512
    #[serde(rename = "rsassa-pss-sha512")]
    RsaSsaPssSha512,
}

/// Wrapper for a key's ID.
#[derive(PartialEq, Eq, Hash)]
pub struct KeyId(Vec<u8>);

impl KeyId {
    /// Parse a key ID from a base64 string.
    pub fn from_string(string: &str) -> Result<Self> {
        if string.len() != 44 {
            bail!(ErrorKind::IllegalArgument(
                "Base64 key ID must be 44 characters long".into(),
            ));
        }
        Ok(KeyId(BASE64.decode(string.as_bytes())?))
    }
}

impl Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KeyId({})", BASE64.encode(&self.0))
    }
}

impl Serialize for KeyId {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        BASE64.encode(&self.0).serialize(ser)
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let string: String = Deserialize::deserialize(de)?;
        KeyId::from_string(&string).map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

/// A structure that contains a `Signature` and associated data for verifying it.
#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    key_id: KeyId,
    scheme: SignatureScheme,
    value: SignatureValue,
}

impl Signature {
    /// An immutable reference to the `KeyId` of the key that produced the signature.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// An immutable reference to the `SignatureScheme` used to create this signature.
    pub fn scheme(&self) -> &SignatureScheme {
        &self.scheme
    }

    /// An immutable reference to the `SignatureValue`.
    pub fn value(&self) -> &SignatureValue {
        &self.value
    }
}

/// Wrapper for the value of a hash digest.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct HashValue(Vec<u8>);

impl HashValue {
    /// Create a new `HashValue` from the given digest bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        HashValue(bytes)
    }

    /// An immutable reference to the bytes of the hash value.
    pub fn value(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for HashValue {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        BASE64.encode(&self.0).serialize(ser)
    }
}

impl<'de> Deserialize<'de> for HashValue {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        let bytes = BASE64.decode(s.as_bytes()).map_err(|e| {
            DeserializeError::custom(format!("Base64: {:?}", e))
        })?;
        Ok(HashValue(bytes))
    }
}

impl Debug for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HashValue({})", BASE64.encode(&self.0))
    }
}

impl Display for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64.encode(&self.0))
    }
}

/// The available hash algorithms.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// SHA256 as describe in [RFC-6234](https://tools.ietf.org/html/rfc6234)
    #[serde(rename = "sha256")]
    Sha256,
    /// SHA512 as describe in [RFC-6234](https://tools.ietf.org/html/rfc6234)
    #[serde(rename = "sha512")]
    Sha512,
}
