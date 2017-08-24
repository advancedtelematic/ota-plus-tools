use json;
use std::fs::{DirBuilder, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use tempfile::NamedTempFile;
use toml;

use config::Config;
use crypto::{KeyPair, KeyType};
use error::{Error, ErrorKind, Result, ResultExt};
use interchange::{DataInterchange, Json, InterchangeType};
use tuf::{TargetsMetadata, SignedMetadata};

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

    pub fn set_unsigned_targets(&self, targets: &TargetsMetadata, force: bool) -> Result<()> {
        let temp = self.new_tempfile()?;
        match self.config.app().interchange() {
            InterchangeType::Json => {
                Json::to_writer(&temp, targets).chain_err(|| "Failed to write temp json metadata")?;
                self.persist_targets(temp, false, force)
            }
        }
    }

    pub fn unsigned_targets(&self) -> Result<TargetsMetadata> {
        let file = File::open(self.targets_path(false))?;
        match self.config.app().interchange() {
            InterchangeType::Json => Ok(json::from_reader(file)?)
        }
    }

    pub fn set_signed_targets<I>(&self, signed: &SignedMetadata<I, TargetsMetadata>, force: bool) -> Result<()>
        where I: DataInterchange
    {
        self.check_interchange(I::typ())?;
        let temp = self.new_tempfile()?;
        match self.config.app().interchange() {
            InterchangeType::Json => {
                Json::to_writer(&temp, signed).chain_err(|| "Failed to write temp json metadata")?;
                self.persist_targets(temp, true, force)
            }
        }
    }

    pub fn signed_targets<I: DataInterchange>(&self) -> Result<SignedMetadata<I, TargetsMetadata>> {
        self.check_interchange(I::typ())?;
        let file = File::open(self.targets_path(true))?;
        match self.config.app().interchange() {
            InterchangeType::Json => Ok(json::from_reader(file)?)
        }
    }

    pub fn add_key(&self, key: &KeyPair, name: &str) -> Result<()> {
        let path = self.path.join("keys").join(name);
        if path.exists() {
            bail!(ErrorKind::Runtime(format!("Key already exists: {}", name)))
        }

        let mut file = File::create(&path)
            .chain_err(|| format!("Could not create path {:?}", path))?;
        file.write_all(key.priv_key())?;
        Ok(())
    }

    pub fn get_key(&self, name: &str) -> Result<KeyPair> {
        let path = self.path.join("keys").join(name);
        if ! path.exists() {
            bail!(ErrorKind::Runtime(format!("Key not found: {}", name)))
        }
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        // FIXME: actual keytype
        KeyPair::from(KeyType::Rsa, data)
    }

    fn new_tempfile(&self) -> Result<NamedTempFile> {
        NamedTempFile::new_in(&self.path.join("temp")).chain_err(|| "Failed to create temp file")
    }

    fn targets_path(&self, signed: bool) -> PathBuf {
        self.path
            .join("metadata")
            .join(if signed { "signed" } else { "unsigned" })
            .join(format!("targets.{}", self.config.app().interchange().extension()))
    }

    fn persist_targets(&self, file: NamedTempFile, signed: bool, force: bool) -> Result<()> {
        let path = self.targets_path(signed);
        let save = if force { file.persist(path) } else { file.persist_noclobber(path) };
        save.map(|_| ())
            .map_err(|e| -> Error { e.into() })
            .chain_err(|| "Persist targets failure")
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
