use json;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fs::{DirBuilder, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use tempfile::NamedTempFile;
use toml;

use config::Config;
use crypto::{KeyPair, KeyType};
use error::{Error, ErrorKind, Result, ResultExt};
use interchange::{DataInterchange, Json, InterchangeType};
use tuf::{Metadata, Role, RootMetadata, TargetsMetadata, SignedMetadata};

pub struct Cache {
    path: PathBuf,
    config: Config,
}

impl Cache {
    pub fn new<P: Into<PathBuf>>(path: P, config: Config) -> Result<Self> {
        let path = path.into();
        for subdir in &[
            PathBuf::from("keys"),
            PathBuf::from("metadata").join("live"),
            PathBuf::from("metadata").join("signed"),
            PathBuf::from("metadata").join("unsigned"),
            PathBuf::from("temp"),
        ] {
            DirBuilder::new()
                .recursive(true)
                .create(path.join(subdir))
                .chain_err(|| format!("Failed to create dir `{:?}`", subdir))?;
        }

        let mut file = File::create(path.join("config.toml"))
            .chain_err(|| "Failed to create `config.toml`")?;
        file.write_all(&toml::to_vec(&config)?)?;

        Ok(Cache { path, config })
    }

    pub fn try_from<P: Into<PathBuf>>(path: P) -> Result<Self> {
        let path = path.into();
        let mut file = File::open(path.join("config.toml"))
            .chain_err(|| "Failed to open `config.toml`")?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .chain_err(|| "Failed to read `config.toml`")?;
        let config = toml::from_slice(&buf)?;
        Ok(Cache { path, config })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn set_signed_root<I>(&self, signed: &SignedMetadata<I, RootMetadata>, force: bool) -> Result<()>
        where I: DataInterchange
    {
        self.write_signed(self.metadata_path(Role::Root, true), signed, force)
    }

    pub fn set_unsigned_root(&self, root: &RootMetadata, force: bool) -> Result<()> {
        self.write_metadata(self.metadata_path(Role::Root, false), root, force)
    }

    pub fn get_signed_root<I: DataInterchange>(&self) -> Result<SignedMetadata<I, RootMetadata>> {
        self.read_signed(Role::Root)
    }

    pub fn get_unsigned_root(&self) -> Result<RootMetadata> {
        self.read_unsigned(Role::Root)
    }

    pub fn set_signed_targets<I>(&self, signed: &SignedMetadata<I, TargetsMetadata>, force: bool) -> Result<()>
        where I: DataInterchange
    {
        self.write_signed(self.metadata_path(Role::Targets, true), signed, force)
    }

    pub fn set_unsigned_targets(&self, targets: &TargetsMetadata, force: bool) -> Result<()> {
        self.write_metadata(self.metadata_path(Role::Targets, false), targets, force)
    }

    pub fn get_signed_targets<I: DataInterchange>(&self) -> Result<SignedMetadata<I, TargetsMetadata>> {
        self.read_signed(Role::Targets)
    }

    pub fn get_unsigned_targets(&self) -> Result<TargetsMetadata> {
        self.read_unsigned(Role::Targets)
    }

    pub fn add_key(&self, key: &KeyPair, role: Role) -> Result<()> {
        let path = self.path.join("keys").join(format!("{}", role));
        if path.exists() {
            bail!(ErrorKind::Runtime(format!("{} key already exists", role)))
        }
        let mut file = File::create(&path)
            .chain_err(|| format!("Could not create path {:?}", path))?;
        file.write_all(key.priv_key())?;
        Ok(())
    }

    pub fn get_key(&self, role: Role) -> Result<KeyPair> {
        let path = self.path.join("keys").join(format!("{}", role));
        if ! path.exists() {
            bail!(ErrorKind::Runtime(format!("{} key not found", role)))
        }
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        // FIXME: actual keytype
        KeyPair::from(KeyType::Rsa, data)
    }

    fn read_signed<I, M>(&self, role: Role) -> Result<SignedMetadata<I, M>>
        where I: DataInterchange,
              M: Metadata + DeserializeOwned
    {
        self.check_interchange(I::typ())?;
        let file = File::open(self.metadata_path(role, true))?;
        match self.config.app().interchange() {
            InterchangeType::Json => Ok(json::from_reader(file)?)
        }
    }

    fn write_signed<I, M>(&self, path: PathBuf, signed: &SignedMetadata<I, M>, force: bool) -> Result<()>
        where I: DataInterchange,
              M: Metadata + Serialize
    {
        self.check_interchange(I::typ())?;
        self.write_metadata(path, signed, force)
    }

    fn read_unsigned<D: DeserializeOwned>(&self, role: Role) -> Result<D> {
        let file = File::open(self.metadata_path(role, false))?;
        match self.config.app().interchange() {
            InterchangeType::Json => Ok(json::from_reader(file)?)
        }
    }

    fn write_metadata<S: Serialize>(&self, path: PathBuf, data: &S, force: bool) -> Result<()> {
        match self.config.app().interchange() {
            InterchangeType::Json => {
                let temp = self.new_tempfile()?;
                Json::to_writer(&temp, data).chain_err(|| "Failed to write temp json metadata")?;
                self.persist_file(path, temp, force)
            }
        }
    }

    fn new_tempfile(&self) -> Result<NamedTempFile> {
        NamedTempFile::new_in(&self.path.join("temp")).chain_err(|| "Failed to create temp file")
    }

    fn metadata_path(&self, role: Role, signed: bool) -> PathBuf {
        self.path
            .join("metadata")
            .join(if signed { "signed" } else { "unsigned" })
            .join(format!("{}.{}", role, self.config.app().interchange().extension()))
    }

    fn persist_file(&self, path: PathBuf, temp: NamedTempFile, force: bool) -> Result<()> {
        let save = if force { temp.persist(path) } else { temp.persist_noclobber(path) };
        save.map(|_| ())
            .map_err(|e| -> Error { e.into() })
            .chain_err(|| "Write to file failed")
    }

    fn check_interchange(&self, typ: InterchangeType) -> Result<()> {
        if typ != self.config.app().interchange() {
            let fmt = self.config.app().interchange();
            let msg = format!("Cache interchange format {:?} did not match argument {:?}", fmt, typ);
            bail!(ErrorKind::IllegalArgument(msg))
        } else {
            Ok(())
        }
    }
}
