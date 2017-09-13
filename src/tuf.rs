//! TUF metadata.

use chrono::DateTime;
use chrono::offset::Utc;
use serde::de::{Deserialize, Deserializer, DeserializeOwned, Error as DeserializeError};
use serde::ser::{Serialize, Serializer, Error as SerializeError};
use pem::{self, Pem};
use std::collections::{HashSet, HashMap};
use std::fmt::{self, Display, Debug};
use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::str::FromStr;

use crypto::{self, HashAlgorithm, HashValue, KeyId, KeyPair, Signature, PubKeyValue};
use error::{Error, Result, ErrorKind, ResultExt};
use interchange::DataInterchange;
use shims;

/// The TUF role.
#[derive(Debug, PartialEq, Serialize, Deserialize, Hash, Eq, Clone, Copy)]
pub enum Role {
    /// The root role.
    #[serde(rename = "root")]
    Root,
    /// The snapshot role.
    #[serde(rename = "snapshot")]
    Snapshot,
    /// The targets role.
    #[serde(rename = "targets")]
    Targets,
    /// The timestamp role.
    #[serde(rename = "timestamp")]
    Timestamp,
}

impl Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Role::Root => write!(f, "root"),
            &Role::Snapshot => write!(f, "snapshot"),
            &Role::Targets => write!(f, "targets"),
            &Role::Timestamp => write!(f, "timestamp"),
        }
    }
}

impl FromStr for Role {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_ref() {
            "root" => Ok(Role::Root),
            "snapshot" => Ok(Role::Snapshot),
            "targets" => Ok(Role::Targets),
            "timestamp" => Ok(Role::Timestamp),
            _ => bail!(ErrorKind::IllegalArgument(format!("Unknown role: {}", s))),
        }
    }
}
/// Top level trait used for role metadata.
pub trait Metadata: Debug + PartialEq + Serialize + DeserializeOwned {
    /// The role associated with the metadata.
    fn role() -> Role;
}

/// A piece of raw metadata with attached signatures.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedMetadata<D: DataInterchange, M: Metadata> {
    signatures: Vec<Signature>,
    signed: D::RawData,
    #[serde(skip_serializing, skip_deserializing)]
    _interchange: PhantomData<D>,
    #[serde(skip_serializing, skip_deserializing)]
    _metadata: PhantomData<M>,
}

impl<D: DataInterchange, M: Metadata> SignedMetadata<D, M> {
    /// Create new signed metadata from a given piece of metadata and a private key.
    pub fn from(metadata: &M, key_pair: &KeyPair) -> Result<Self> {
        let data = D::serialize(metadata)?;
        let canonical = D::canonicalize(&data)?;
        let sig = key_pair.sign(&canonical)?;
        Ok(SignedMetadata {
            signatures: vec![sig],
            signed: data,
            _interchange: PhantomData,
            _metadata: PhantomData,
        })
    }

    pub fn add_signature(&mut self, key_pair: &KeyPair) -> Result<()> {
        let data = D::serialize(&self.signed)?;
        let canonical = D::canonicalize(&data)?;
        let sig = key_pair.sign(&canonical)?;
        self.signatures.push(sig);
        Ok(())
    }

    /// An immutable reference to the metadata's signatures.
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// A mutable reference to the metadata's signature.
    pub fn signatures_mut(&mut self) -> &mut Vec<Signature> {
        &mut self.signatures
    }

    /// An immutable reference to the raw data that will be signed.
    pub fn signed(&self) -> &D::RawData {
        &self.signed
    }
}

/// Metadata for the root role.
#[derive(Debug, Clone, PartialEq)]
pub struct RootMetadata {
    version: u32,
    expires: DateTime<Utc>,
    keys: HashMap<KeyId, PublicKey>,
    roles: HashMap<Role, RoleKeys>,
    consistent_snapshot: bool,
}

impl RootMetadata {
    /// Create new root metadata (with validation).
    pub fn new(
        version: u32,
        expires: DateTime<Utc>,
        keys: HashMap<KeyId, PublicKey>,
        roles: HashMap<Role, RoleKeys>,
        consistent_snapshot: bool,
    ) -> Result<Self> {
        if version < 1 {
            let msg = format!(
                "Metadata version must be greater than zero. Found: {}",
                version
            );
            bail!(ErrorKind::IllegalArgument(msg));
        }
        Ok(RootMetadata {
            version,
            expires,
            keys,
            roles,
            consistent_snapshot,
        })
    }

    /// Set the metadata's version.
    pub fn set_version(&mut self, version: u32) {
        self.version = version;
    }

    /// The metadata's version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// An immutable reference to when the metadata expires.
    pub fn expires(&self) -> &DateTime<Utc> {
        &self.expires
    }

    /// An immutable reference to the map of all keys used by this metadata.
    pub fn keys(&self) -> &HashMap<KeyId, PublicKey> {
        &self.keys
    }

    /// A mutable reference to the map of all keys used by this metadata.
    pub fn keys_mut(&mut self) -> &mut HashMap<KeyId, PublicKey> {
        &mut self.keys
    }

    /// An immutable reference to the map of roles and their definitions.
    pub fn roles(&self) -> &HashMap<Role, RoleKeys> {
        &self.roles
    }

    /// A mutable reference to the map of roles and their definitions.
    pub fn roles_mut(&mut self) -> &mut HashMap<Role, RoleKeys> {
        &mut self.roles
    }

    /// Wheter this repo uses the consistent snapshot feature.
    pub fn consistent_snapshot(&self) -> bool {
        self.consistent_snapshot
    }

    /// Add a key to the given role.
    pub fn add_key(&mut self, role: Role, key_id: KeyId, pubkey: PublicKey) -> Result<()> {
        if let Some(keys) = self.roles.get_mut(&role) {
            let _ = keys.key_ids.insert(key_id.clone());
        } else {
            bail!(ErrorKind::IllegalArgument("role not found".into()));
        }
        let _ = self.keys.insert(key_id, pubkey);
        Ok(())
    }

    /// Remove a key from the role.
    pub fn remove_key(&mut self, role: Role, key_id: &KeyId) -> Result<()> {
        if let Some(keys) = self.roles.get_mut(&role) {
            let _ = keys.key_ids.remove(key_id);
        } else {
            bail!(ErrorKind::IllegalArgument("role not found".into()));
        }

        if self.roles
            .iter()
            .filter(|&(_, def)| def.key_ids.contains(key_id))
            .collect::<Vec<_>>()
            .len() == 0
        {
            let _ = self.keys.remove(key_id);
        }

        if let None = self.keys.remove(key_id) {
            bail!(ErrorKind::IllegalArgument("key not found".into()));
        }
        Ok(())
    }
}

impl Metadata for RootMetadata {
    fn role() -> Role {
        Role::Root
    }
}

impl Serialize for RootMetadata {
    fn serialize<S: Serializer>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error> {
        shims::RootMetadata::from(self)
            .map_err(|e| SerializeError::custom(format!("{:?}", e)))?
            .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for RootMetadata {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::RootMetadata = Deserialize::deserialize(de)?;
        intermediate.try_into().map_err(|e| {
            DeserializeError::custom(format!("{:?}", e))
        })
    }
}


/// Metadata for the targets role.
#[derive(Debug, Clone, PartialEq)]
pub struct TargetsMetadata {
    version: u32,
    expires: DateTime<Utc>,
    targets: HashMap<TargetPath, TargetDescription>,
}

impl TargetsMetadata {
    /// Create new `TargetsMetadata`.
    pub fn new(
        version: u32,
        expires: DateTime<Utc>,
        targets: HashMap<TargetPath, TargetDescription>,
    ) -> Result<Self> {
        if version < 1 {
            let msg = format!(
                "Metadata version must be greater than zero. Found: {}",
                version
            );
            bail!(ErrorKind::IllegalArgument(msg));
        }
        Ok(TargetsMetadata {
            version,
            expires,
            targets,
        })
    }

    /// The version number.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// An immutable reference to the metadata's expiration `DateTime`.
    pub fn expires(&self) -> &DateTime<Utc> {
        &self.expires
    }

    /// An immutable reference to the descriptions of targets.
    pub fn targets(&self) -> &HashMap<TargetPath, TargetDescription> {
        &self.targets
    }

    /// Add a target to the metadata.
    pub fn add_target(&mut self, path: TargetPath, description: TargetDescription) {
        let _ = self.targets.insert(path, description);
    }

    /// Remove a target from the metadata.
    pub fn remove_target(&mut self, path: &TargetPath) {
        let _ = self.targets.remove(path);
    }
}

impl Metadata for TargetsMetadata {
    fn role() -> Role {
        Role::Targets
    }
}

impl Serialize for TargetsMetadata {
    fn serialize<S: Serializer>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error> {
        shims::TargetsMetadata::from(self)
            .map_err(|e| SerializeError::custom(format!("{:?}", e)))?
            .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for TargetsMetadata {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::TargetsMetadata = Deserialize::deserialize(de)?;
        intermediate.try_into().map_err(|e| {
            DeserializeError::custom(format!("{:?}", e))
        })
    }
}

/// Wrapper for a path to a target.
#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize)]
pub struct TargetPath(String);

impl TargetPath {
    // TODO add sanitation rules to this
    /// Create a new target path from the given string.
    pub fn new(path: String) -> Result<Self> {
        Ok(TargetPath(path))
    }

    /// Split `TargetPath` into components that can be joined to create URL paths, Unix paths, or
    /// Windows paths.
    ///
    /// ```
    /// use ota_plus::tuf::TargetPath;
    ///
    /// let path = TargetPath::new("foo/bar".into()).unwrap();
    /// assert_eq!(path.components(), ["foo".to_string(), "bar".to_string()]);
    /// ```
    pub fn components(&self) -> Vec<String> {
        self.0.split('/').map(|s| s.to_string()).collect()
    }

    /// Return whether this path is the child of another path.
    ///
    /// ```
    /// use ota_plus::tuf::TargetPath;
    ///
    /// let path1 = TargetPath::new("foo".into()).unwrap();
    /// let path2 = TargetPath::new("foo/bar".into()).unwrap();
    /// assert!(!path2.is_child(&path1));
    ///
    /// let path1 = TargetPath::new("foo/".into()).unwrap();
    /// let path2 = TargetPath::new("foo/bar".into()).unwrap();
    /// assert!(path2.is_child(&path1));
    ///
    /// let path2 = TargetPath::new("foo/bar/baz".into()).unwrap();
    /// assert!(path2.is_child(&path1));
    ///
    /// let path2 = TargetPath::new("wat".into()).unwrap();
    /// assert!(!path2.is_child(&path1))
    /// ```
    pub fn is_child(&self, parent: &Self) -> bool {
        if !parent.0.ends_with('/') {
            return false;
        }

        self.0.starts_with(&parent.0)
    }

    /// Whether or not the current target is available at the end of the given chain of target
    /// paths. For the chain to be valid, each target path in a group must be a child of of all
    /// previous groups.
    // TODO this is hideous and uses way too much clone/heap but I think recursively,
    // so here we are
    pub fn matches_chain(&self, parents: &[HashSet<TargetPath>]) -> bool {
        if parents.is_empty() {
            return false;
        } else if parents.len() == 1 {
            return parents[0].iter().any(|p| p == self || self.is_child(p));
        }

        let new = parents[1..]
            .iter()
            .map(|group| {
                group
                    .iter()
                    .filter(|parent| {
                        parents[0].iter().any(
                            |p| parent.is_child(p) || parent == &p,
                        )
                    })
                    .cloned()
                    .collect::<HashSet<_>>()
            })
            .collect::<Vec<_>>();
        self.matches_chain(&*new)
    }
}

impl ToString for TargetPath {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl<'de> Deserialize<'de> for TargetPath {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        TargetPath::new(s).map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

/// Description of a target, used in verification.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TargetDescription {
    length: u64,
    hashes: HashMap<HashAlgorithm, HashValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    custom: Option<TargetCustom>,
}

impl TargetDescription {
    /// Create a new `TargetDescription`.
    ///
    /// Note: Creating this manually could lead to errors, and the `from_reader` method is
    /// preferred.
    pub fn new(
        length: u64,
        hashes: HashMap<HashAlgorithm, HashValue>,
        custom: Option<TargetCustom>,
    ) -> Result<Self> {
        if hashes.is_empty() {
            bail!(ErrorKind::IllegalArgument(
                "Cannot have empty set of hashes".into(),
            ));
        }

        Ok(TargetDescription {
            length,
            hashes,
            custom,
        })
    }

    /// Read the from the given reader and calculate the length and hash values.
    ///
    /// ```
    /// extern crate data_encoding;
    /// extern crate ota_plus;
    /// use data_encoding::BASE64;
    /// use ota_plus::crypto::{HashAlgorithm,HashValue};
    /// use ota_plus::tuf::TargetDescription;
    ///
    /// fn main() {
    ///     let bytes: &[u8] = b"it was a pleasure to burn";
    ///
    ///     let s = "Rd9zlbzrdWfeL7gnIEi05X+Yv2TCpy4qqZM1N72ZWQs=";
    ///     let sha256 = HashValue::new(BASE64.decode(s.as_bytes()).unwrap());
    ///
    ///     let target_description =
    ///         TargetDescription::from_reader(bytes, &[HashAlgorithm::Sha256], None).unwrap();
    ///     assert_eq!(target_description.length(), bytes.len() as u64);
    ///     assert_eq!(target_description.hashes().get(&HashAlgorithm::Sha256), Some(&sha256));
    ///
    ///     let s ="tuIxwKybYdvJpWuUj6dubvpwhkAozWB6hMJIRzqn2jOUdtDTBg381brV4K\
    ///         BU1zKP8GShoJuXEtCf5NkDTCEJgQ==";
    ///     let sha512 = HashValue::new(BASE64.decode(s.as_bytes()).unwrap());
    ///
    ///     let target_description =
    ///         TargetDescription::from_reader(bytes, &[HashAlgorithm::Sha512], None).unwrap();
    ///     assert_eq!(target_description.length(), bytes.len() as u64);
    ///     assert_eq!(target_description.hashes().get(&HashAlgorithm::Sha512), Some(&sha512));
    /// }
    /// ```
    pub fn from_reader<R: Read>(
        read: R,
        hash_algs: &[HashAlgorithm],
        custom: Option<TargetCustom>,
    ) -> Result<Self> {
        let (length, hashes) = crypto::calculate_hashes(read, hash_algs)?;
        Ok(TargetDescription {
            length,
            hashes,
            custom,
        })
    }

    /// The maximum length of the target.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// An immutable reference to the list of calculated hashes.
    pub fn hashes(&self) -> &HashMap<HashAlgorithm, HashValue> {
        &self.hashes
    }
}

impl<'de> Deserialize<'de> for TargetDescription {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::TargetDescription = Deserialize::deserialize(de)?;
        intermediate.try_into().map_err(|e| {
            DeserializeError::custom(format!("{:?}", e))
        })
    }
}

/// Custom metadata optionally attached to a `TargetDescription`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TargetCustom {
    name: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri: Option<String>,
    #[serde(rename = "hardwareIds")]
    #[serde(skip_serializing_if = "Option::is_none")]
    hardware_ids: Option<Vec<String>>,
    #[serde(rename = "createdAt")]
    created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    updated_at: DateTime<Utc>,
    #[serde(rename = "releaseCounter")]
    release_counter: u32,
}

impl TargetCustom {
    /// Create a new `TargetCustom`.
    pub fn new(
        name: String,
        version: String,
        uri: Option<String>,
        hardware_ids: Option<Vec<String>>,
        release_counter: u32,
    ) -> Self {
        let created_at = Utc::now();
        let updated_at = created_at.clone();
        TargetCustom {
            name,
            version,
            uri,
            hardware_ids,
            created_at,
            updated_at,
            release_counter,
        }
    }
}

/// The
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RoleKeys {
    // TODO needs custom ser/de to ensure deterministic ordering.
    #[serde(rename = "keyids")]
    key_ids: HashSet<KeyId>,
    threshold: u32,
}

impl RoleKeys {
    /// An immutable reference to the role's key IDs.
    pub fn key_ids(&self) -> &HashSet<KeyId> {
        &self.key_ids
    }

    /// A mutable reference to the role's key IDs.
    pub fn key_ids_mut(&mut self) -> &mut HashSet<KeyId> {
        &mut self.key_ids
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
// TODO this needs a custom deserialize because it's possible that the key_type/key_val don't match
// and we are currently doing no validatoin
// TODO instead, just kill this because it belongs in `crypto`.
pub struct PublicKey {
    #[serde(rename = "keytype")]
    key_type: crypto::KeyType,
    #[serde(rename = "keyval")]
    key_val: PublicKeyValue,
}

impl PublicKey {
    pub fn from_file<P: Into<PathBuf>>(path: P) -> Result<Self> {
        let path = path.into();
        let mut file = File::open(&path).chain_err(|| {
            format!("Failed to open path {:?}", path)
        })?;

        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        let (key_val, key_type) = PubKeyValue::from_spki(&mut buf)?;

        PublicKey::from_pubkey(key_type.clone(), &key_val)
    }

    /// Convert from a `PubKeyValue`.
    // TODO this shouldn't exist, the type in `crypto` should handle this.
    pub fn from_pubkey(typ: crypto::KeyType, public: &crypto::PubKeyValue) -> Result<Self> {
        Ok(PublicKey {
            key_type: typ,
            key_val: PublicKeyValue {
                public: {
                    let p = Pem {
                        tag: "PUBLIC KEY".into(),
                        contents: (*public).to_vec(),
                    };
                    pem::encode(&p).replace("\r", "").trim().into()
                },
            },
        })
    }
}

/// A public key's value.
// TODO this shouldn't exist, the type in `crypto` should handle this.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PublicKeyValue {
    public: String,
}

// TODO this shouldn't exist, the type in `crypto` should handle this.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PrivateKey {
    #[serde(rename = "keytype")]
    key_type: crypto::KeyType,
    #[serde(rename = "keyval")]
    key_val: PrivateKeyValue,
}

impl PrivateKey {
    pub fn private_pem(&self) -> &str {
        &self.key_val.private
    }

    pub fn as_key_pair(&self) -> Result<KeyPair> {
        let parsed = pem::parse(&self.key_val.private)?;
        Ok(KeyPair::from(parsed.contents)?)
    }
}

// TODO this shouldn't exist, the type in `crypto` should handle this.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PrivateKeyValue {
    private: String,
}
