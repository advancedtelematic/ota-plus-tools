extern crate chrono;
extern crate clap;
extern crate data_encoding;
#[macro_use]
extern crate error_chain;
extern crate ota_plus;

use chrono::offset::Utc;
use chrono::prelude::*;
use clap::{App, ArgMatches, AppSettings, SubCommand, Arg};
use data_encoding::{BASE64, HEXLOWER};
use ota_plus::cache::Cache;
use ota_plus::crypto::{KeyType, KeyPair, HashAlgorithm, HashValue};
use ota_plus::tuf::{TargetsMetadata, TargetPath, TargetDescription};
use std::collections::HashMap;
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::str::FromStr;

error_chain! {
    foreign_links {
        Io(io::Error);
        DataEncodingDecode(data_encoding::DecodeError);
    }

    links {
        OtaPlus(ota_plus::error::Error, ota_plus::error::ErrorKind);
    }

    errors {
        IllegalArgument(s: String) {
            description("An illegal argument was supplied")
            display("Illegal argument: {}", s)
        }
        Runtime(s: String) {
            description("A runtime error occurred")
            display("{}", s)
        }
    }
}

fn main() {
    match run_main(parser().get_matches()) {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            // TODO pretty print the error
            writeln!(&mut io::stderr(), "{:?}", e).unwrap();
            std::process::exit(1);
        }
    }
}

fn run_main(matches: ArgMatches) -> Result<()> {
    let path: Result<_> = matches
        .value_of("path")
        .map(PathBuf::from)
        .or_else(|| env::home_dir().map(|p| p.join(".ota-plus")))
        .ok_or_else(|| {
            ErrorKind::IllegalArgument("Missing `path`.".into()).into()
        });
    // this looks dumb, but the compiler requires it
    let path = path?;

    if let Some(_) = matches.subcommand_matches("init") {
        cmd_init(path)
    } else if let Some(matches) = matches.subcommand_matches("keygen") {
        let typ = matches.value_of("type").unwrap();
        let typ = KeyType::from_str(&typ)?;
        cmd_keygen(&typ)
    } else if let Some(matches) = matches.subcommand_matches("tuf") {
        if let Some(matches) = matches.subcommand_matches("targets") {
            if let Some(matches) = matches.subcommand_matches("init") {
                let version = matches.value_of("version").unwrap().parse::<u32>().unwrap();
                let expires = matches.value_of("expires").unwrap();
                let expires = Utc.datetime_from_str(expires, "%FT%TZ").unwrap();
                let force = matches.is_present("force");
                cmd_targets_init(path, version, expires, force)
            } else if let Some(matches) = matches.subcommand_matches("target") {
                if let Some(matches) = matches.subcommand_matches("add") {
                    let target = TargetPath::new(matches.value_of("target").unwrap().into())
                        .unwrap();
                    let length = matches.value_of("length").unwrap().parse::<u64>().unwrap();
                    let sha256 = matches.value_of("sha256");
                    let sha512 = matches.value_of("sha512");
                    let encoding = Encoding::from_str(&matches.value_of("encoding").unwrap())
                        .unwrap();
                    let force = matches.is_present("force");
                    cmd_targets_target_add(path, target, force, length, sha256, sha512, encoding)
                } else if let Some(matches) = matches.subcommand_matches("remove") {
                    let target = TargetPath::new(matches.value_of("target").unwrap().into())
                        .unwrap();
                    cmd_targets_target_remove(path, &target)
                } else {
                    unreachable!()
                }
            } else {
                unreachable!()
            }
        } else {
            unreachable!()
        }
    } else {
        unreachable!()
    }
}

enum Encoding {
    Hexlower,
    Base64,
}

impl Encoding {
    fn decode(&self, s: &str) -> Result<Vec<u8>> {
        match *self {
            Encoding::Hexlower => Ok(HEXLOWER.decode(s.as_bytes())?),
            Encoding::Base64 => Ok(BASE64.decode(s.as_bytes())?),
        }
    }
}

impl FromStr for Encoding {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "hexlower" => Ok(Encoding::Hexlower),
            "base64" => Ok(Encoding::Base64),
            _ => Err(
                ErrorKind::IllegalArgument(format!("Unknown encoding: {}", s)).into(),
            ),
        }
    }
}

fn is_positive_u64(s: String) -> ::std::result::Result<(), String> {
    s.parse::<u64>().map(|_| ()).map_err(|_| format!("Not u64"))
}

fn is_natural_u32(s: String) -> ::std::result::Result<(), String> {
    s.parse::<u32>().map_err(|_| format!("Not u32")).and_then(
        |x| if x <
            1
        {
            Err("Version cannot be less than 1".into())
        } else {
            Ok(())
        },
    )
}

fn is_datetime(s: String) -> ::std::result::Result<(), String> {
    Utc.datetime_from_str(&s, "%FT%TZ").map(|_| ()).map_err(
        |e| {
            format!("{:?}", e)
        },
    )
}

fn is_target_path(s: String) -> ::std::result::Result<(), String> {
    TargetPath::new(s).map(|_| ()).map_err(|e| {
        format!("Illegal target path: {}", e)
    })
}

fn parser<'a, 'b>() -> App<'a, 'b> {
    App::new("ota-plus")
        .version(env!("CARGO_PKG_VERSION"))
        .about("CLI tool for interacting with OTA+")
        .settings(&[AppSettings::SubcommandRequiredElseHelp])
        .arg(
            Arg::with_name("path")
                .help(
                    "The path to the settings and local cache. Defaults to `~/.ota-plus`.",
                )
                .short("p")
                .long("path")
                .takes_value(true)
                .global(true),
        )
        .subcommand(subcmd_init())
        .subcommand(subcmd_keygen())
        .subcommand(subcmd_tuf())
}

fn subcmd_init<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name("init").about("Initialize the local cache")
}

fn subcmd_keygen<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name("keygen")
        .about(
            "Generate private keys and print them as PKCS#8v2 DER to STDOUT",
        )
        .arg(
            Arg::with_name("type")
                .takes_value(true)
                .default_value("ed25519")
                .possible_values(&["ed25519"]),
        )
}

fn subcmd_tuf<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name("tuf")
        .about("Interact with a TUF repository")
        .settings(&[AppSettings::SubcommandRequiredElseHelp])
        .subcommand(subsubcmd_targets())
}

fn subsubcmd_targets<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name("targets")
        .about("Manipulate metadata for the `targets` role")
        .settings(&[AppSettings::SubcommandRequiredElseHelp])
        .subcommand(
            SubCommand::with_name("init")
                .about("Initialize empty `targets` metadata")
                .arg(
                    Arg::with_name("version")
                        .short("v")
                        .long("version")
                        .takes_value(true)
                        .required(true)
                        .validator(is_natural_u32),
                )
                .arg(
                    Arg::with_name("expires")
                        .short("e")
                        .long("expires")
                        .takes_value(true)
                        .required(true)
                        .validator(is_datetime),
                )
                .arg(
                    Arg::with_name("force")
                        .help("Create the `targets` metadata even it already exists")
                        .short("f")
                        .long("force"),
                )
        )
        .subcommand(
            SubCommand::with_name("target")
                .about("Add or remove targets")
                .settings(&[AppSettings::SubcommandRequiredElseHelp])
                .subcommand(
                    SubCommand::with_name("add")
                        .about("Add a target to the staged metadata")
                        .arg(
                            Arg::with_name("target")
                                .help("The target's name")
                                .required(true)
                                .takes_value(true)
                                .validator(is_target_path),
                        )
                        .arg(
                            Arg::with_name("force")
                                .help("Add the target even it already exists")
                                .short("f")
                                .long("force"),
                        )
                        .arg(
                            Arg::with_name("length")
                                .help("The upper bound of the size of the target in bytes")
                                .short("l")
                                .long("length")
                                .required(true)
                                .validator(is_positive_u64),
                        )
                        .arg(
                            Arg::with_name("sha256")
                                .help("The SHA256 hash of the target")
                                .long("sha256"),
                        )
                        .arg(
                            Arg::with_name("sha512")
                                .help("The SHA512 hash of the target")
                                .long("sha512"),
                        )
                        // TODO url
                        .arg(
                            Arg::with_name("encoding")
                                .help("The encoding used for the hashes")
                                .default_value("hexlower")
                                .possible_values(&["hexlower", "base64"]),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("remove")
                        .about("Remove a target from the staged metadata")
                        .arg(
                            Arg::with_name("target")
                                .help("The target's name")
                                .required(true)
                                .takes_value(true)
                                .validator(is_target_path),
                        ),
                ),
        )

}

fn get_cache(path: PathBuf) -> Result<Cache> {
    Cache::try_from(path).chain_err(|| "Could not initialize the cache")
}

fn cmd_keygen(typ: &KeyType) -> Result<()> {
    match KeyPair::new_key_bytes(typ) {
        Ok(bs) => io::stdout().write(&bs).map(|_| ()).map_err(|e| e.into()),
        Err(e) => Err(e.into()),
    }
}

fn cmd_init(path: PathBuf) -> Result<()> {
    Cache::new(path, None).map(|_| ()).map_err(|e| e.into())
}

fn cmd_targets_init(path: PathBuf, version: u32, expires: DateTime<Utc>, force: bool) -> Result<()> {
    let cache = get_cache(path)?;
    let targets = TargetsMetadata::new(version, expires, HashMap::new())
        .chain_err(|| "Couldn't create `targets` metadata")?;
    cache.unsigned_targets(&targets, force).map_err(|e| e.into())
}

fn cmd_targets_target_add(
    path: PathBuf,
    target: TargetPath,
    force: bool,
    length: u64,
    sha256: Option<&str>,
    sha512: Option<&str>,
    encoding: Encoding,
) -> Result<()> {
    let cache = get_cache(path)?;
    let mut hashes = HashMap::new();
    match sha256 {
        Some(s) => {
            let _ = hashes.insert(HashAlgorithm::Sha256, HashValue::new(encoding.decode(s)?));
        }
        None => (),
    };
    match sha512 {
        Some(s) => {
            let _ = hashes.insert(HashAlgorithm::Sha512, HashValue::new(encoding.decode(s)?));
        }
        None => (),
    };

    let description = TargetDescription::new(length, hashes)?;
    let mut targets = cache.load_targets()?;
    if targets.targets().contains_key(&target) && !force {
        bail!(ErrorKind::Runtime("Target already exists".into()))
    }
    targets.add_target(target, description);
    Ok(())
}

fn cmd_targets_target_remove(path: PathBuf, target: &TargetPath) -> Result<()> {
    let cache = get_cache(path)?;
    let mut targets = cache.load_targets()?;
    targets.remove_target(target);
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_parser() {
        let _ = parser();
    }
}
