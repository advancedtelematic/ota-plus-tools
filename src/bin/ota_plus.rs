extern crate clap;
extern crate ota_plus;

use clap::{App, ArgMatches, AppSettings, SubCommand, Arg};
use ota_plus::cache::Cache;
use ota_plus::crypto::{KeyType, KeyPair};
use ota_plus::error::{Result, ErrorKind};
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::str::FromStr;

fn main() {
    match run_main(parser().get_matches()) {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            writeln!(&mut io::stderr(), "{:?}", e).unwrap();
            std::process::exit(1);
        }
    }
}

fn run_main(matches: ArgMatches) -> Result<()> {
    let path: Result<_> = matches
        .value_of("path")
        .map(PathBuf::from)
        .or_else(|| env::home_dir())
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
    } else if let Some(_) = matches.subcommand_matches("tuf") {
        Ok(()) // TODO
    } else {
        unreachable!() // because of AppSettings::SubcommandRequiredElseHelp
    }
}

fn parser<'a, 'b>() -> App<'a, 'b> {
    App::new("ota-plus")
        .version(env!("CARGO_PKG_VERSION"))
        .about("CLI tool for interacting with OTA+")
        .settings(&[AppSettings::SubcommandRequiredElseHelp])
        .arg(
            Arg::with_name("path")
                .help(
                    "The path to the settings and local cache. Defaults to HOME.",
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
    SubCommand::with_name("tuf").about("Interact with a TUF repository")
    // TODO
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_parser() {
        let _ = parser();
    }
}
