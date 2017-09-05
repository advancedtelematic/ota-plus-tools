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
pub struct RootMetadata {
    #[serde(rename = "_type")]
    typ: tuf::Role,
    version: u32,
    expires: String,
    keys: HashMap<crypto::KeyId, tuf::PublicKey>,
    roles: HashMap<tuf::Role, tuf::RoleKeys>,
    consistent_snapshot: bool,
}

impl RootMetadata {
    pub fn from(tuf: &tuf::RootMetadata) -> Result<Self> {
        Ok(RootMetadata {
            typ: tuf::Role::Root,
            version: tuf.version(),
            expires: format_datetime(&tuf.expires()),
            keys: tuf.keys().clone(),
            roles: tuf.roles().clone(),
            consistent_snapshot: tuf.consistent_snapshot(),
        })
    }

    pub fn try_into(self) -> Result<tuf::RootMetadata> {
        if self.typ != tuf::Role::Root {
            let msg = format!(
                "Attempted to decode root metadata labeled as {:?}",
                self.typ
            );
            bail!(ErrorKind::Encoding(msg));
        }
        let expires = parse_datetime(&self.expires)?;
        tuf::RootMetadata::new(
            self.version,
            expires,
            self.keys,
            self.roles,
            self.consistent_snapshot,
        )
    }
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
            let msg = format!(
                "Attempted to decode targets metadata labeled as {:?}",
                self.typ
            );
            bail!(ErrorKind::Encoding(msg));
        }
        tuf::TargetsMetadata::new(self.version, parse_datetime(&self.expires)?, self.targets)
    }
}


#[derive(Deserialize)]
pub struct TargetDescription {
    length: u64,
    hashes: HashMap<crypto::HashAlgorithm, crypto::HashValue>,
    custom: Option<tuf::TargetCustom>,
}

impl TargetDescription {
    pub fn try_into(self) -> Result<tuf::TargetDescription> {
        tuf::TargetDescription::new(self.length, self.hashes, self.custom)
    }
}
