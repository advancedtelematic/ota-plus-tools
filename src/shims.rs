use chrono::offset::Utc;
use chrono::prelude::*;
use std::collections::HashMap;

use crypto;
use error::{Result, ErrorKind};
use tuf;

fn parse_datetime(ts: &str) -> Result<DateTime<Utc>> {
    Utc.datetime_from_str(ts, "%FT%TZ").map_err(|e| e.into())
}

fn format_datetime(ts: &DateTime<Utc>) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        ts.year(),
        ts.month(),
        ts.day(),
        ts.hour(),
        ts.minute(),
        ts.second()
    )
}

#[derive(Serialize, Deserialize)]
pub struct TargetsMetadata {
    #[serde(rename = "_type")]
    typ: tuf::Role,
    version: u32,
    expires: String,
    targets: HashMap<tuf::TargetPath, tuf::TargetDescription>,
}

impl TargetsMetadata {
    pub fn from(tuf: &tuf::TargetsMetadata) -> Result<Self> {
        Ok(TargetsMetadata {
            typ: tuf::Role::Targets,
            version: tuf.version(),
            expires: format_datetime(&tuf.expires()),
            targets: tuf.targets().clone(),
        })
    }

    pub fn try_into(self) -> Result<tuf::TargetsMetadata> {
        if self.typ != tuf::Role::Targets {
            bail!(ErrorKind::Encoding(format!(
                "Attempted to decode targets metdata labeled as {:?}",
                self.typ
            )));
        }

        tuf::TargetsMetadata::new(self.version, parse_datetime(&self.expires)?, self.targets)
    }
}

#[derive(Deserialize)]
pub struct TargetDescription {
    size: u64,
    hashes: HashMap<crypto::HashAlgorithm, crypto::HashValue>,
}

impl TargetDescription {
    pub fn try_into(self) -> Result<tuf::TargetDescription> {
        tuf::TargetDescription::new(self.size, self.hashes)
    }
}
