use std::fs::{DirBuilder, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use toml;

use config::Config;
use error::Result;

pub struct Cache {
    path: PathBuf,
    config: Config,
}

impl Cache {
    pub fn new<P>(path: P, config: Option<Config>) -> Result<Self>
    where
        P: Into<PathBuf>,
    {
        let path = path.into();

        for p in &["keys", "metadata"] {
            DirBuilder::new().recursive(true).create(path.join(p))?
        }

        let config = config.unwrap_or_default();

        let mut file = File::create(path.join("config.toml"))?;
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

        let mut file = File::open(path.join("config.toml"))?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        let config = toml::from_slice(&buf)?;

        Ok(Cache {
            path: path.into(),
            config: config,
        })
    }
}
