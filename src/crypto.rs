//! Crypto structs and functions.

use curve25519_dalek::curve::{CompressedEdwardsY, ExtendedPoint};
use data_encoding::{BASE64, HEXLOWER};
use derp::{self, Der, Tag};
use ring::digest::{self, SHA256, SHA512};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, RSAKeyPair, RSASigningState, RSA_PSS_SHA256};
use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use serde::ser::{Serialize, Serializer};
use std::collections::HashMap;
use std::fmt::{self, Debug, Display};
use std::io::{Read, Write};
use std::ops::Deref;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::Arc;
use untrusted::Input;

use error::{Error, ErrorKind, Result};
use tuf;

/// 1.2.840.113549.1.1.1 rsaEncryption(PKCS #1)
const RSA_SPKI_OID: &'static [u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// 1.3.101.112 curveEd25519(EdDSA 25519 signature algorithm)
const ED25519_SPKI_OID: &'static [u8] = &[0x2b, 0x65, 0x70];

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
            Ok(0) => break,
            Ok(read_bytes) => {
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
    pub_point_array.copy_from_slice(pub_point);

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

/// The type of cryptographic key.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq)]
pub enum KeyType {
    /// [Ed25519](https://ed25519.cr.yp.to/)
    #[serde(rename = "ED25519")]
    Ed25519,

    /// [RSA](https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29)
    #[serde(rename = "RSA")]
    Rsa,
}

impl KeyType {
    fn from_oid(oid: &[u8]) -> Result<Self> {
        match oid {
            x if x == RSA_SPKI_OID => Ok(KeyType::Rsa),
            x if x == ED25519_SPKI_OID => Ok(KeyType::Ed25519),
            x => {
                bail!(format!(
                    "Unknown OID: {}",
                    x.iter().map(|b| format!("{:x}", b)).collect::<String>()
                ))
            }
        }
    }
}

impl FromStr for KeyType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_ref() {
            "ed25519" | "ED25519" => Ok(KeyType::Ed25519),
            "rsa" | "RSA" => Ok(KeyType::Rsa),
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
    Rsa(Arc<RSAKeyPair>),
}

impl KeyPairInner {
    fn typ(&self) -> KeyType {
        match *self {
            KeyPairInner::Ed25519(_) => KeyType::Ed25519,
            KeyPairInner::Rsa(_) => KeyType::Rsa,
        }
    }
}


/// A public/privat key pair.
pub struct KeyPair {
    inner: KeyPairInner,
    key_id: KeyId,
    priv_key: PrivKeyValue,
    pub_key: PubKeyValue,
}

impl KeyPair {
    /// Generate a new key pair of the given type.
    ///
    /// Note: Ed25519 will be generated by Rust, but RSA requires a shellout to `openssl`.
    pub fn new(typ: KeyType) -> Result<Self> {
        match typ {
            KeyType::Ed25519 => {
                let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                    .map(|a| a.to_vec())
                    .map_err(|_| {
                        ErrorKind::Crypto("Failed to generate Ed25519 key".into())
                    })?;
                let pair =
                    Ed25519KeyPair::from_pkcs8(Input::from(&pkcs8_bytes))
                        .map_err(|_| ErrorKind::Crypto("Failed to parse PKCS#8 bytes".into()))?;
                let pub_key = wrap_ed25519_public_point(pair.public_key_bytes())?;
                Ok(KeyPair {
                    inner: KeyPairInner::Ed25519(pair),
                    key_id: KeyId::calculate(&pub_key),
                    pub_key: PubKeyValue(pub_key),
                    priv_key: PrivKeyValue(pkcs8_bytes),
                })
            }

            KeyType::Rsa => {
                let gen = Command::new("openssl")
                    .args(
                        &[
                            "genpkey",
                            "-algorithm",
                            "RSA",
                            "-pkeyopt",
                            "rsa_keygen_bits:2048",
                            "-pkeyopt",
                            "rsa_keygen_pubexp:65537",
                            "-outform",
                            "der",
                        ],
                    )
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()?;
                let priv_key = gen.wait_with_output()?.stdout;
                Self::rsa_from_priv(priv_key)
            }
        }
    }

    /// Initialize the `KeyPair` of a known type from the DER bytes of the private key.
    pub fn from(priv_key: Vec<u8>) -> Result<Self> {
        match Ed25519KeyPair::from_pkcs8(Input::from(&priv_key)) {
            Ok(pair) => {
                let pub_key = wrap_ed25519_public_point(pair.public_key_bytes())?;
                Ok(KeyPair {
                    inner: KeyPairInner::Ed25519(pair),
                    key_id: KeyId::calculate(&pub_key),
                    pub_key: PubKeyValue(pub_key),
                    priv_key: PrivKeyValue(priv_key),
                })
            }
            Err(e) => {
                match Self::rsa_from_priv(priv_key) {
                    Ok(key) => Ok(key),
                    Err(e2) => {
                        bail!(ErrorKind::Crypto(format!(
                            "Failed to parse Ed25519: {:?}\nFailed to parse RSA: {:?}",
                            e,
                            e2
                        )))
                    }
                }
            }
        }
    }

    pub fn typ(&self) -> KeyType {
        self.inner.typ()
    }

    /// An immutable reference to the public key's value.
    pub fn pub_key(&self) -> &PubKeyValue {
        &self.pub_key
    }

    /// An immutable reference to the private key's value.
    pub fn priv_key(&self) -> &PrivKeyValue {
        &self.priv_key
    }

    /// An immutable reference to the key's ID.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// Clone the internal values to make this key into a serializable public key that the OTA+
    /// backend understands.
    pub fn as_public_key(&self) -> Result<tuf::PublicKey> {
        tuf::PublicKey::from_pubkey(self.inner.typ(), self.pub_key())
    }

    /// Sign the given message with this key.
    pub fn sign(&self, msg: &[u8]) -> Result<Signature> {
        let (sig, method) = match self.inner {
            KeyPairInner::Ed25519(ref ed) => {
                (
                    SignatureValue(ed.sign(msg).as_ref().into()),
                    SignatureMethod::Ed25519,
                )
            }

            KeyPairInner::Rsa(ref rsa) => {
                let mut signing_state = RSASigningState::new(rsa.clone()).map_err(|_| {
                    ErrorKind::Crypto("Could not initialize RSA signing state.".into())
                })?;
                let rng = SystemRandom::new();
                let mut buf = vec![0; signing_state.key_pair().public_modulus_len()];
                signing_state
                    .sign(&RSA_PSS_SHA256, &rng, msg, &mut buf)
                    .map_err(|_| ErrorKind::Crypto("Failed to sign message.".into()))?;
                (SignatureValue(buf), SignatureMethod::RsaSsaPssSha256)
            }
        };

        Ok(Signature {
            key_id: self.key_id.clone(),
            method: method,
            sig: sig,
        })
    }

    fn rsa_from_priv(priv_key: Vec<u8>) -> Result<Self> {
        let pair = RSAKeyPair::from_der(Input::from(&priv_key)).map_err(|_| {
            ErrorKind::Crypto("Could not parse DER RSA private key".into())
        })?;
        if pair.public_modulus_len() < 256 {
            let len = pair.public_modulus_len() * 8;
            let err = format!("RSA public modulus must be >= 2048. Size: {}", len);
            bail!(ErrorKind::IllegalArgument(err));
        }
        Ok(KeyPair {
            inner: KeyPairInner::Rsa(Arc::new(pair)),
            key_id: KeyId::calculate(&Self::rsa_get_pub(&priv_key, "DER")?),
            pub_key: PubKeyValue(Self::rsa_get_pub(&priv_key, "PEM")?),
            priv_key: PrivKeyValue(priv_key),
        })
    }

    fn rsa_get_pub(priv_key: &[u8], outform: &str) -> Result<Vec<u8>> {
        let mut pub_key = Command::new("openssl")
            .args(&["rsa", "-inform", "DER", "-pubout", "-outform", outform])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        pub_key.stdin.as_mut().expect("stdin").write_all(priv_key)?;
        Ok(pub_key.wait_with_output()?.stdout)
    }
}

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
    fn serialize<S: Serializer>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error> {
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
pub enum SignatureMethod {
    /// [Ed25519](https://ed25519.cr.yp.to/)
    #[serde(rename = "ed25519")]
    Ed25519,
    /// [RSASSA-PSS](https://tools.ietf.org/html/rfc5756) calculated over SHA256
    #[serde(rename = "rsassa-pss")]
    RsaSsaPssSha256,
    /// [RSASSA-PSS](https://tools.ietf.org/html/rfc5756) calculated over SHA512
    #[serde(rename = "rsassa-pss512")]
    RsaSsaPssSha512,
}

/// Wrapper for a key's ID.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct KeyId(Vec<u8>);

impl Deref for KeyId {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl KeyId {
    /// Calculate a key ID, assuming the given bytes are a correctly formatted key.
    pub fn calculate(public_key: &[u8]) -> Self {
        let mut context = digest::Context::new(&SHA256);
        context.update(&public_key);
        KeyId(context.finish().as_ref().to_vec())
    }

    /// Decode a hex-lower encoded key into a key ID.
    pub fn from_string(string: &str) -> Result<Self> {
        if string.len() != 64 {
            bail!(ErrorKind::IllegalArgument(
                "Base16 key ID must be 64 characters long".into(),
            ));
        }
        Ok(KeyId(HEXLOWER.decode(string.as_bytes())?))
    }
}

impl Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KeyId({})", HEXLOWER.encode(&self.0))
    }
}

impl Serialize for KeyId {
    fn serialize<S: Serializer>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error> {
        HEXLOWER.encode(&self.0).serialize(ser)
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
    method: SignatureMethod,
    sig: SignatureValue,
}

impl Signature {
    /// An immutable reference to the `KeyId` of the key that produced the signature.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// An immutable reference to the `SignatureMethod` used to create this signature.
    pub fn method(&self) -> &SignatureMethod {
        &self.method
    }

    /// An immutable reference to the `SignatureValue`.
    pub fn sig(&self) -> &SignatureValue {
        &self.sig
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
    fn serialize<S: Serializer>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error> {
        HEXLOWER.encode(&self.0).serialize(ser)
    }
}

impl<'de> Deserialize<'de> for HashValue {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        let bytes = HEXLOWER.decode(s.as_bytes()).map_err(|e| {
            DeserializeError::custom(format!("Base64: {:?}", e))
        })?;
        Ok(HashValue(bytes))
    }
}

impl Debug for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HashValue({})", self)
    }
}

impl Display for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", HEXLOWER.encode(&self.0))
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

/// Wrapper around a private key's bytes.
pub struct PrivKeyValue(Vec<u8>);

impl Deref for PrivKeyValue {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

/// Wrapper around the DER bytes of a public key.
#[derive(PartialEq)]
pub struct PubKeyValue(Vec<u8>);

impl PubKeyValue {
    pub fn from_spki(der_bytes: &[u8]) -> Result<(Self, KeyType)> {
        let input = Input::from(der_bytes);

        Ok(input.read_all(derp::Error::Read, |input| {
            derp::nested(input, Tag::Sequence, |input| {
                let typ = derp::nested(input, Tag::Sequence, |input| {
                    let typ = derp::expect_tag_and_get_value(input, Tag::Oid)?;

                    let typ = KeyType::from_oid(typ.as_slice_less_safe()).map_err(|_| {
                        derp::Error::WrongValue
                    })?;

                    // for RSA / ed25519 this is null, so don't both parsing it
                    let _ = derp::read_null(input)?;
                    Ok(typ)
                })?;
                let value = derp::bit_string_with_no_unused_bits(input)?;
                Ok((PubKeyValue(value.as_slice_less_safe().to_vec()), typ))
            })
        })?)
    }
}

impl Debug for PubKeyValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PubKeyValue({})", BASE64.encode(&self.0))
    }
}

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
            let key = KeyPair::new(KeyType::Ed25519).unwrap();
            let pub_key = match &key.inner {
                &KeyPairInner::Ed25519(ref ed) => ed.public_key_bytes(),
                _ => panic!(),
            };
            wrap_ed25519_public_point(pub_key).unwrap();
        }
    }
}
