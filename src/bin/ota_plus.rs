extern crate chrono;
extern crate clap;
extern crate data_encoding;
extern crate env_logger;
#[macro_use]
extern crate error_chain;
extern crate ota_plus;
extern crate serde_json as json;
extern crate reqwest;
extern crate uuid;

use chrono::offset::Utc;
use chrono::prelude::*;
use clap::{App, ArgMatches, AppSettings, SubCommand, Arg};
use data_encoding::{BASE64, HEXLOWER};
use ota_plus::cache::Cache;
use ota_plus::config::{Config, AppConfig, AuthConfig};
use ota_plus::crypto::{KeyPair, KeyType, HashAlgorithm, HashValue, PubKeyTuf};
use ota_plus::http::Http;
use ota_plus::interchange::{InterchangeType, Json};
use ota_plus::tuf::{SignedMetadata, TargetsMetadata, TargetPath, TargetCustom, TargetDescription};
use reqwest::{Response, StatusCode};
use std::collections::HashMap;
use std::env;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::str::FromStr;

error_chain! {
    foreign_links {
        Io(io::Error);
        Json(json::Error);
        DataEncodingDecode(data_encoding::DecodeError);
        Http(reqwest::Error);
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
    env_logger::init().expect("start logger");

    let matches = parser().get_matches();
    let outcome = || -> Result<()> {
        let root = matches.value_of("root")
            .map(PathBuf::from)
            .or_else(|| env::home_dir().map(|path| path.join(".ota-plus")))
            .ok_or_else(|| ErrorKind::IllegalArgument("Missing `path`.".into()))?;

        match matches.subcommand() {
            ("init", Some(sub)) => cmd_init(root, sub),
            ("keygen", Some(sub)) => cmd_keygen(root, sub),
            ("tuf", Some(sub)) => match sub.subcommand() {
                ("pushkey", Some(sub)) => cmd_tuf_pushkey(root, sub),
                ("targets", Some(sub)) => match sub.subcommand() {
                    ("init", Some(sub)) => cmd_tuf_targets_init(root, sub),
                    ("add", Some(sub)) => cmd_tuf_targets_add(root, sub),
                    ("remove", Some(sub)) => cmd_tuf_targets_remove(root, sub),
                    ("sign", _) => cmd_tuf_targets_sign(root),
                    ("push", _) => cmd_tuf_targets_push(root),
                    _ => unreachable!()
                },
                _ => unreachable!()
            },
            _ => unreachable!()
        }
    }();

    outcome.unwrap_or_else(|err| {
        // TODO pretty print the error
        writeln!(&mut io::stderr(), "{:?}", err).unwrap();
        std::process::exit(1);
    })
}

fn parser<'a, 'b>() -> App<'a, 'b> {
    App::new("ota-plus")
        .version(env!("CARGO_PKG_VERSION"))
        .about("CLI tool for interacting with OTA+")
        .settings(&[AppSettings::SubcommandRequiredElseHelp])
        .arg(
            Arg::with_name("root")
                .help("The root path of the local cache. Defaults to `~/.ota-plus`.")
                .long("root")
                .takes_value(true)
                .global(true),
        )
        .subcommand(subcmd_init())
        .subcommand(subcmd_keygen())
        .subcommand(subcmd_tuf())
}

fn subcmd_init<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name("init")
        .about("Initialize the local cache")
        .arg(
            Arg::with_name("client_id")
                .long("client-id")
                .takes_value(true)
                .required(true)
        )
        .arg(
            Arg::with_name("client_secret")
                .long("client-secret")
                .takes_value(true)
                .required(true)
        )
        .arg(
            Arg::with_name("repo_id")
                .long("repo-id")
                .takes_value(true)
                .required(true)
        )
        .arg(
            Arg::with_name("tuf_url")
                .long("tuf-url")
                .takes_value(true)
                .required(true)
        )
        .arg(
            Arg::with_name("token_url")
                .long("token-url")
                .takes_value(true)
                .required(true)
        )
}

fn subcmd_keygen<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name("keygen")
        .about("Generate private keys and print them as PKCS#8v2 DER to STDOUT")
        .arg(
            Arg::with_name("role")
                .short("r")
                .long("role")
                .takes_value(true)
                .required(true)
                .possible_values(&["root", "targets", "timestamp", "snapshot"]),
        )
        .arg(
            Arg::with_name("type")
                .short("t")
                .long("type")
                .takes_value(true)
                .possible_values(&["rsa"]),
                // FIXME(PRO-3849): bouncy castle ed25519 key parsing
        )
}

fn subcmd_tuf<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name("tuf")
        .about("Interact with a TUF repository")
        .settings(&[AppSettings::SubcommandRequiredElseHelp])
        .subcommand(
            SubCommand::with_name("pushkey")
                .about("Push a new public key to the remote TUF repo")
                .arg(
                    Arg::with_name("role")
                        .short("r")
                        .long("role")
                        .takes_value(true)
                        .required(true)
                        .possible_values(&["root", "targets", "timestamp", "snapshot"])
                )
        )
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
                ),
        )
        .subcommand(
            SubCommand::with_name("add")
                .about("Add a target to the staged metadata")
                .arg(
                    Arg::with_name("target")
                        .help("The target's name")
                        .short("t")
                        .long("target")
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
                        .takes_value(true)
                        .validator(is_positive_u64),
                )
                .arg(
                    Arg::with_name("url")
                        .help("The URL referencing the target")
                        .long("url")
                        .takes_value(true)
                        .required(true)
                )
                .arg(
                    Arg::with_name("encoding")
                        .help("The encoding used for the hashes")
                        .default_value("hexlower")
                        .possible_values(&["hexlower", "base64"])
                )
                .arg(
                    Arg::with_name("sha256")
                        .help("The SHA256 hash of the target")
                        .long("sha256")
                        .takes_value(true)
                )
                .arg(
                    Arg::with_name("sha512")
                        .help("The SHA512 hash of the target")
                        .long("sha512")
                        .takes_value(true)
                )
                .arg(
                    Arg::with_name("hardware-id")
                        .help("Restrict the target to specific hardware IDs")
                        .long("hardware-id")
                        .takes_value(true)
                        .multiple(true)
                )
        )
        .subcommand(
            SubCommand::with_name("remove")
                .about("Remove a target from the staged metadata")
                .arg(
                    Arg::with_name("target")
                        .help("The target's name")
                        .short("t")
                        .required(true)
                        .takes_value(true)
                        .validator(is_target_path),
                ),
        )
        .subcommand(SubCommand::with_name("sign").about("Sign the targets metadata"))
        .subcommand(SubCommand::with_name("push").about("Push the signed targets metadata to the TUF repo"))
}

fn is_positive_u64(s: String) -> ::std::result::Result<(), String> {
    s.parse::<u64>().map(|_| ()).map_err(|_| format!("Not u64"))
}

fn is_natural_u32(s: String) -> ::std::result::Result<(), String> {
    s.parse::<u32>()
        .map_err(|_| format!("Not a u32: {}", s))
        .and_then(|x| if x < 1 { Err("Version cannot be less than 1".into()) } else { Ok(()) })
}

fn is_datetime(s: String) -> ::std::result::Result<(), String> {
    Utc.datetime_from_str(&s, "%FT%TZ").map(|_| ()).map_err(|e| format!("{:?}", e))
}

fn is_target_path(s: String) -> ::std::result::Result<(), String> {
    TargetPath::new(s).map(|_| ()).map_err(|e| format!("Illegal target path: {}", e))
}


fn cmd_init(root: PathBuf, matches: &ArgMatches) -> Result<()> {
    let client_id = matches.value_of("client_id").unwrap().parse().unwrap();
    let client_secret = matches.value_of("client_secret").unwrap();
    let repo_id = matches.value_of("repo_id").unwrap();
    let tuf_url = matches.value_of("tuf_url").unwrap_or("https://app.atsgarage.com");
    let token_url = matches.value_of("token_url").unwrap_or("https://auth-plus.atsgarage.com");

    let app_conf = AppConfig::new(InterchangeType::Json, tuf_url.into());
    let auth_conf = AuthConfig::new(client_id, client_secret.into(), repo_id.into(), token_url.into());
    Cache::new(root, Config::new(app_conf, auth_conf)).map(|_| ())?;
    Ok(())
}

fn cmd_keygen(root: PathBuf, matches: &ArgMatches) -> Result<()> {
    let role = matches.value_of("role").unwrap();
    let typ = KeyType::from_str(&matches.value_of("type").unwrap())?;
    let key = KeyPair::new(typ)?;
    let cache = get_cache(root)?;
    cache.add_key(&key, role)?;
    Ok(())
}

fn cmd_tuf_pushkey(root: PathBuf, matches: &ArgMatches) -> Result<()> {
    let role = matches.value_of("role").unwrap();
    let cache = get_cache(root)?;
    let key = cache.get_key(role)?;

    let resp = Http::new(cache.config())?
        .put(&format!("{}/keys/targets", cache.config().app().tuf_url()))?
        .json(&PubKeyTuf::from(KeyType::Rsa, key.pub_key())?)?
        .send()?;
    check_status(resp)
}

fn cmd_tuf_targets_init(root: PathBuf, matches: &ArgMatches) -> Result<()> {
    let version = matches.value_of("version").unwrap().parse::<u32>().unwrap();
    let expires = matches.value_of("expires").unwrap();
    let expires = Utc.datetime_from_str(expires, "%FT%TZ").unwrap();
    let force = matches.is_present("force");
    let cache = get_cache(root)?;
    let targets = TargetsMetadata::new(version, expires, HashMap::new())
        .chain_err(|| "Couldn't create `targets` metadata")?;
    cache.set_unsigned_targets(&targets, force)?;
    Ok(())
}

fn cmd_tuf_targets_add(root: PathBuf, matches: &ArgMatches) -> Result<()> {
    let target = TargetPath::new(matches.value_of("target").unwrap().into()).unwrap();
    let length = matches.value_of("length").unwrap().parse::<u64>().unwrap();
    let encoding = Encoding::from_str(&matches.value_of("encoding").unwrap()).unwrap();
    let force = matches.is_present("force");

    let mut hashes = HashMap::new();
    if let Some(s) = matches.value_of("sha256") {
        let _ = hashes.insert(HashAlgorithm::Sha256, HashValue::new(encoding.decode(s)?));
    }
    if let Some(s) = matches.value_of("sha512") {
        let _ = hashes.insert(HashAlgorithm::Sha512, HashValue::new(encoding.decode(s)?));
    }

    let url = matches.value_of("url").unwrap();
    let ids = match matches.values_of("hardware-id") {
        None => None,
        Some(vals) => Some(vals.map(String::from).collect::<Vec<_>>())
    };
    let custom = TargetCustom::new(Some(url.into()), ids);

    let cache = get_cache(root)?;
    let description = TargetDescription::new(length, hashes, Some(custom))?;
    let mut targets = cache.unsigned_targets()?;
    if targets.targets().contains_key(&target) && !force {
        bail!(ErrorKind::Runtime("Target already exists".into()))
    }
    targets.add_target(target, description);
    cache.set_unsigned_targets(&targets, true)?;
    Ok(())
}

fn cmd_tuf_targets_remove(root: PathBuf, matches: &ArgMatches) -> Result<()> {
    let target = TargetPath::new(matches.value_of("target").unwrap().into()).unwrap();
    let cache = get_cache(root)?;
    let mut targets = cache.unsigned_targets()?;
    targets.remove_target(&target);
    cache.set_unsigned_targets(&targets, true)?;
    Ok(())
}

fn cmd_tuf_targets_sign(root: PathBuf) -> Result<()> {
    let cache = get_cache(root)?;
    let key = cache.get_key("targets")?;
    let targets = cache.unsigned_targets()?;
    let signed: SignedMetadata<Json, TargetsMetadata> = SignedMetadata::from(&targets, &key)?;
    cache.set_signed_targets(&signed, true)?;
    Ok(())
}

fn cmd_tuf_targets_push(root: PathBuf) -> Result<()> {
    let cache = get_cache(root)?;
    let resp = Http::new(cache.config())?
        .put(&format!("{}/targets", cache.config().app().tuf_url()))?
        .json(&cache.signed_targets::<Json>()?)?
        .send()?;
    check_status(resp)
}

fn get_cache(root: PathBuf) -> Result<Cache> {
    Cache::try_from(root).chain_err(|| "Could not initialize the cache")
}

fn check_status(mut resp: Response) -> Result<()> {
    match resp.status() {
        StatusCode::Ok | StatusCode::NoContent => Ok(()),
        status => {
            let mut body = Vec::new();
            resp.read_to_end(&mut body).unwrap();
            let err = format!("Status: {}, Body:\n{}", status, String::from_utf8_lossy(&body));
            bail!(ErrorKind::Runtime(err));
        }
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
            _ => Err(ErrorKind::IllegalArgument(format!("Unknown encoding: {}", s)).into()),
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_parser() {
        let _ = parser();
    }
}
