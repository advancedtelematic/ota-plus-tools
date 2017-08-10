extern crate chrono;
extern crate clap;
extern crate ota_plus;

use chrono::offset::Utc;
use chrono::prelude::*;
use clap::{App, ArgMatches, AppSettings, SubCommand, Arg};
use ota_plus::cache::Cache;
use ota_plus::crypto::{KeyType, KeyPair};
use ota_plus::error::{Result, ResultExt, ErrorKind};
use ota_plus::tuf::TargetsMetadata;
use std::collections::HashMap;
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::str::FromStr;

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
        let typ = matches
            .value_of("type")
            .ok_or_else(|| {
                ErrorKind::IllegalArgument("Missing key type.".into()).into()
            })
            .and_then(KeyType::from_str)?;
        cmd_keygen(&typ)
    } else if let Some(matches) = matches.subcommand_matches("tuf") {
        if let Some(matches) = matches.subcommand_matches("targets") {
            if let Some(matches) = matches.subcommand_matches("init") {
                let version = matches.value_of("version").unwrap().parse::<u32>().unwrap();
                let expires = matches.value_of("expires").unwrap();
                let expires = Utc.datetime_from_str(expires, "%FT%TZ").unwrap();
                cmd_targets_init(path, version, expires)
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

fn is_natural_number(s: String) -> ::std::result::Result<(), String> {
    s.parse::<u32>()
        .map_err(|_| format!("Version not u32"))
        .and_then(|x| if x < 1 {
            Err("Version cannot be less than 1".into())
        } else {
            Ok(())
        })
}

fn is_datetime(s: String) -> ::std::result::Result<(), String> {
    Utc.datetime_from_str(&s, "%FT%TZ").map(|_| ()).map_err(
        |e| {
            format!("{:?}", e)
        },
    )
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
                .takes_value(true),
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
                .arg(
                    Arg::with_name("version")
                        .short("v")
                        .long("version")
                        .takes_value(true)
                        .required(true)
                        .validator(is_natural_number),
                )
                .arg(
                    Arg::with_name("expires")
                        .short("e")
                        .long("expires")
                        .takes_value(true)
                        .required(true)
                        .validator(is_datetime),
                ),
        )

}

fn cmd_keygen(typ: &KeyType) -> Result<()> {
    match KeyPair::new_key_bytes(typ) {
        Ok(bs) => io::stdout().write(&bs).map(|_| ()).map_err(|e| e.into()),
        Err(e) => Err(e),
    }
}

fn cmd_init(path: PathBuf) -> Result<()> {
    Cache::new(path, None).map(|_| ())
}

fn cmd_targets_init(path: PathBuf, version: u32, expires: DateTime<Utc>) -> Result<()> {
    let cache = Cache::try_from(path).chain_err(
        || "Could not initialize the cache",
    )?;
    let targets = TargetsMetadata::new(version, expires, HashMap::new())
        .chain_err(|| "Couldn't create `targets` metadata")?;
    cache.unsigned_targets(&targets)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_parser() {
        let _ = parser();
    }
}
