use json;
use std::fs::{DirBuilder, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use tempfile::NamedTempFile;
use toml;

use config::Config;
use error::{Result, ResultExt, Error, ErrorKind};
use interchange::{DataInterchange, Json, InterchangeType};
use tuf::{TargetsMetadata, SignedMetadata};

pub struct Cache {
    path: PathBuf,
    config: Config,
}

impl Cache {
    pub fn new<P>(path: P, config: Config) -> Result<Self>
    where
        P: Into<PathBuf>,
    {
        let path = path.into();

        for p in &[
            PathBuf::from("keys"),
            PathBuf::from("metadata").join("live"),
            PathBuf::from("metadata").join("signed"),
            PathBuf::from("metadata").join("unsigned"),
            PathBuf::from("temp"),
        ]
        {
            DirBuilder::new()
                .recursive(true)
                .create(path.join(p))
                .chain_err(|| format!("Failed to create dir `{:?}`", p))?;
        }

        let mut file = File::create(path.join("config.toml")).chain_err(
            || "Failed to create `config.toml`",
        )?;
        file.write_all(&toml::to_vec(&config)?)?;

        Ok(Cache {
            path: path,
            config: config,
        })
    }

    pub fn try_from<P>(path: P) -> Result<Self>
    where
        P: Into<PathBuf>,
    {
        let path = path.into();

        let mut file = File::open(path.join("config.toml")).chain_err(
            || "Failed to open `config.toml`",
        )?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).chain_err(
            || "Failed to read `config.toml`",
        )?;

        let config = toml::from_slice(&buf)?;

        Ok(Cache {
            path: path.into(),
            config: config,
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    fn tempfile(&self) -> Result<NamedTempFile> {
        NamedTempFile::new_in(&self.path.join("temp")).chain_err(|| "Failed to create temp file")
    }

    pub fn set_unsigned_targets(&self, targets: &TargetsMetadata, force: bool) -> Result<()> {
        let temp = self.tempfile()?;
        match self.config.app().interchange() {
            &InterchangeType::Json => {
                Json::to_writer(&temp, &targets).chain_err(
                    || "Failed to write metadata to temp file",
                )?;

                let path = self.path.join("metadata").join("unsigned").join(format!(
                    "targets.{}",
                    Json::extension()
                ));

                (if force {
                     temp.persist(path)
                 } else {
                     temp.persist_noclobber(path)
                 }).map(|_| ())
                    .map_err(|e| {
                        let e: Error = e.into();
                        e
                    })
                    .chain_err(|| "Temp file persistence failure")
            }
        }
    }

    pub fn unsigned_targets(&self) -> Result<TargetsMetadata> {
        let mut file = File::open(self.path.join("metadata").join("unsigned").join(format!(
            "targets.{}",
            self.config.app().interchange().extension()
        )))?;
        match *self.config.app().interchange() {
            InterchangeType::Json => Ok(json::from_reader(file)?)
        }
    }

    pub fn set_signed_targets<I>(
        &self,
        signed: &SignedMetadata<I, TargetsMetadata>,
        force: bool,
    ) -> Result<()>
    where
        I: DataInterchange,
    {

        let temp = self.tempfile()?;

        if &I::typ() != self.config.app().interchange() {
            bail!(ErrorKind::IllegalArgument(format!(
                "Cache interchange format {:?} did not match argument {:?}",
                self.config.app().interchange(),
                I::typ()
            )))
        }

        match self.config.app().interchange() {
            &InterchangeType::Json => {
                Json::to_writer(&temp, &signed).chain_err(
                    || "Failed to write metadata to temp file",
                )?;

                let path = self.path.join("metadata").join("signed").join(format!(
                    "targets.{}",
                    Json::extension()
                ));

                (if force {
                     temp.persist(path)
                 } else {
                     temp.persist_noclobber(path)
                 }).map(|_| ())
                    .map_err(|e| {
                        let e: Error = e.into();
                        e
                    })
                    .chain_err(|| "Temp file persistence failure")
            }
        }
    }

    pub fn signed_targets<I>(&self) -> Result<SignedMetadata<I, TargetsMetadata>>
    where
        I: DataInterchange
    {
        if &I::typ() != self.config.app().interchange() {
            bail!(ErrorKind::IllegalArgument(format!(
                "Cache interchange format {:?} did not match argument {:?}",
                self.config.app().interchange(),
                I::typ()
            )))
        }

        let mut file = File::open(self.path.join("metadata").join("signed").join(format!(
            "targets.{}",
            self.config.app().interchange().extension()
        )))?;
        match *self.config.app().interchange() {
            InterchangeType::Json => Ok(json::from_reader(file)?)
        }
    }
}
