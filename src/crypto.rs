use curve25519_dalek::curve::{CompressedEdwardsY, ExtendedPoint};
use data_encoding::BASE64;
use derp::Der;
use ring::digest::{self, SHA256, SHA512};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use serde::ser::{Serialize, Serializer};
use std::collections::HashMap;
use std::fmt::{self, Debug, Display};
use std::io::Read;
use std::ops::Deref;
use std::str::FromStr;
use untrusted;

use error::{Error, ErrorKind, Result};

/// 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
const EC_PUBLIC_KEY_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/// 1.2.840.10045.1.1 prime-field (ANSI X9.62 field type)
const PRIME_FIELD_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x01, 0x01];

const PRIME_FIELD: &[u8] = &[
    0x7f,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xed,
];

const FIELD_ELEMENT_A: &[u8] = &[
    0x2A,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0x98,
    0x49,
    0x14,
    0xA1,
    0x44,
];

const FIELD_ELEMENT_B: &[u8] = &[
    0x7B,
    0x42,
    0x5E,
    0xD0,
    0x97,
    0xB4,
    0x25,
    0xED,
    0x09,
    0x7B,
    0x42,
    0x5E,
    0xD0,
    0x97,
    0xB4,
    0x25,
    0xED,
    0x09,
    0x7B,
    0x42,
    0x5E,
    0xD0,
    0x97,
    0xB4,
    0x26,
    0x0B,
    0x5E,
    0x9C,
    0x77,
    0x10,
    0xC8,
    0x64,
];

const BASE_POINT: &[u8] = &[
    0x04,
    0x2a,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xaa,
    0xad,
    0x24,
    0x5a,
    0x20,
    0xae,
    0x19,
    0xa1,
    0xb8,
    0xa0,
    0x86,
    0xb4,
    0xe0,
    0x1e,
    0xdd,
    0x2c,
    0x77,
    0x48,
    0xd1,
    0x4c,
    0x92,
    0x3d,
    0x4d,
    0x7e,
    0x6d,
    0x7c,
    0x61,
    0xb2,
    0x29,
    0xe9,
    0xc5,
    0xa2,
    0x7e,
    0xce,
    0xd3,
    0xd9,
];

const ORDER: &[u8] = &[
    0x10,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x14,
    0xde,
    0xf9,
    0xde,
    0xa2,
    0xf7,
    0x9c,
    0xd6,
    0x58,
    0x12,
    0x63,
    0x1a,
    0x5c,
    0xf5,
    0xd3,
    0xed,
];

const COFACTOR: &[u8] = &[0x08];

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

                for (_, context) in hashes.iter_mut() {
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

fn calculate_key_id(public_key: &[u8]) -> KeyId {
    let mut context = digest::Context::new(&SHA256);
    context.update(&public_key);
    KeyId(context.finish().as_ref().to_vec())
}

/// Takes the public point on the elliptic curve (raw, 32 bytes) and wraps it in the PKCS#8 wrapper
/// the OTA+ backend uses.
///
/// See also: [RFC 3279](http://www.rfc-base.org/txt/rfc-3279.txt)
fn wrap_ed25519_public_point(pub_point: &[u8]) -> Result<Vec<u8>> {
    if pub_point.len() != 32 {
        bail!(ErrorKind::IllegalArgument(
            "Curve public point must be 32 bytes".into(),
        ))
    }

    let mut pub_point_array = [0; 32];
    for i in 0..32 {
        pub_point_array[0] = pub_point[i];
    }

    let expanded = expand_pub_key(&pub_point_array)?;

    let mut pub_key = Vec::new();
    {
        let mut der = Der::new(&mut pub_key);
        der.sequence(|der| {
            der.oid(EC_PUBLIC_KEY_OID)?;
            der.sequence(|der| {
                der.positive_integer(&[0x01])?;
                der.sequence(|der| {
                    der.oid(PRIME_FIELD_OID)?;
                    der.integer(PRIME_FIELD)
                })?;
                der.sequence(|der| {
                    der.octet_string(FIELD_ELEMENT_A)?;
                    der.octet_string(FIELD_ELEMENT_B)
                })?;
                der.octet_string(BASE_POINT)?;
                der.positive_integer(ORDER)?;
                der.positive_integer(COFACTOR)
            })
        })?;
        der.bit_string(0, &expanded)?;
    }

    Ok(pub_key)
}

fn expand_pub_key(pub_key: &[u8; 32]) -> Result<[u8; 65]> {
    let ExtendedPoint {
        X: x,
        Y: y,
        Z: _,
        T: _,
    } = CompressedEdwardsY(pub_key.clone())
        .decompress()
        .ok_or_else(|| {
            ErrorKind::Crypto("Could not decompress curve point.".into())
        })?;
    let x = x.to_bytes();
    let y = y.to_bytes();

    let mut out = [0; 65];
    out[0] = 0x04; // signals to BouncyCastle that this is not compressed

    for i in 0..32 {
        out[1 + i] = x[i];
        out[1 + 32 + i] = y[i];
    }

    Ok(out)
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
    key_id: KeyId,
    priv_key: PrivKeyValue,
    pub_key: PubKeyValue,
}

impl KeyPair {
    pub fn new(typ: &KeyType) -> Result<Self> {
        match *typ {
            KeyType::Ed25519 => {
                let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                    .map(|a| a.to_vec())
                    .map_err(|_| {
                        ErrorKind::Crypto("Failed to generate Ed25519 key".into())
                    })?;

                let pair =
                    Ed25519KeyPair::from_pkcs8(untrusted::Input::from(&pkcs8_bytes))
                        .map_err(|_| ErrorKind::Crypto("Failed to parse PKCS#8 bytes".into()))?;

                let pub_key = wrap_ed25519_public_point(pair.public_key_bytes())?;
                let key_id = calculate_key_id(&pub_key);

                Ok(KeyPair {
                    inner: KeyPairInner::Ed25519(pair),
                    key_id: key_id,
                    pub_key: PubKeyValue(pub_key),
                    priv_key: PrivKeyValue(pkcs8_bytes),
                })
            }
        }
    }

    pub fn pub_key(&self) -> &PubKeyValue {
        &self.pub_key
    }

    pub fn priv_key(&self) -> &PrivKeyValue {
        &self.priv_key
    }
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
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

pub struct PrivKeyValue(Vec<u8>);

impl Deref for PrivKeyValue {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(PartialEq)]
pub struct PubKeyValue(Vec<u8>);

impl Deref for PubKeyValue {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ring_to_bouncy_castle_conversion() {
        // doing it many times because of intermittent failures
        for _ in 0..1000 {
            let key = KeyPair::new(&KeyType::Ed25519).unwrap();
            let pub_key = match &key.inner {
                &KeyPairInner::Ed25519(ref ed) => ed.public_key_bytes(),
            };
            wrap_ed25519_public_point(pub_key).unwrap();
        }
    }
}
