use chrono::DateTime;
use chrono::offset::Utc;
use serde::de::{Deserialize, Deserializer, DeserializeOwned, Error as DeserializeError};
use serde::ser::{Serialize, Serializer, Error as SerializeError};
use std::collections::{HashSet, HashMap};
use std::fmt::{self, Display, Debug};
use std::io::Read;
use std::marker::PhantomData;

use crypto::{self, Signature, HashValue, HashAlgorithm, KeyPair};
use error::{Result, ErrorKind};
use interchange::DataInterchange;
use shims;

/// The TUF role.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Role {
    /// The root role.
    Root,
    /// The snapshot role.
    Snapshot,
    /// The targets role.
    Targets,
    /// The timestamp role.
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
    pub fn from(targets: &TargetsMetadata, key_pair: &KeyPair) -> Result<Self> {
        let data = D::serialize(&targets)?;
        let canonical = D::canonicalize(&data)?;
        let sig = key_pair.sign(&canonical)?;
        Ok(SignedMetadata {
            signatures: vec![sig],
            signed: data,
            _interchange: PhantomData,
            _metadata: PhantomData
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
            let msg = format!("Metadata version must be greater than zero. Found: {}", version);
            bail!(ErrorKind::IllegalArgument(msg));
        }
        Ok(TargetsMetadata { version, expires, targets })
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

    pub fn add_target(&mut self, path: TargetPath, description: TargetDescription) {
        let _ = self.targets.insert(path, description);
    }

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
        intermediate.try_into().map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

/// Wrapper for a path to a target.
#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize)]
pub struct TargetPath(String);

impl TargetPath {
    // TODO add sanitation rules to this
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

        let new = parents[1..].iter()
            .map(|group| {
                group.iter()
                    .filter(|parent| parents[0].iter().any(|p| parent.is_child(p) || parent == &p))
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
        custom: Option<TargetCustom>
    ) -> Result<Self> {
        if hashes.is_empty() {
            bail!(ErrorKind::IllegalArgument("Cannot have empty set of hashes".into()));
        }

        Ok(TargetDescription { length, hashes, custom })
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
        custom: Option<TargetCustom>
    ) -> Result<Self> {
        let (length, hashes) = crypto::calculate_hashes(read, hash_algs)?;
        Ok(TargetDescription { length, hashes, custom })
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
        intermediate.try_into().map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

/// Custom metadata optionally attached to a `TargetDescription`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TargetCustom {
    #[serde(skip_serializing_if = "Option::is_none")]
    uri: Option<String>,
    #[serde(rename = "hardwareIds")]
    #[serde(skip_serializing_if = "Option::is_none")]
    hardware_ids: Option<Vec<String>>,
}

impl TargetCustom {
    /// Create a new `TargetCustom`.
    pub fn new(uri: Option<String>, hardware_ids: Option<Vec<String>>) -> Self {
        TargetCustom { uri, hardware_ids }
    }
}
