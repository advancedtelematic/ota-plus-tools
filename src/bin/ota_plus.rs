extern crate chrono;
extern crate clap;
extern crate data_encoding;
extern crate env_logger;
#[macro_use]
extern crate error_chain;
extern crate pem;
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
use ota_plus::crypto::{KeyId, KeyPair, KeyType, HashAlgorithm, HashValue};
use ota_plus::http::Http;
use ota_plus::interchange::{InterchangeType, Json};
use ota_plus::tuf::{PublicKey, Role, RootMetadata, SignedMetadata, TargetsMetadata,
                    TargetPath, TargetCustom, TargetDescription};
use reqwest::{Response, StatusCode};
use std::collections::HashMap;
use std::fs::File;
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
        let cache = matches.value_of("cache")
            .map(PathBuf::from)
            .or_else(|| env::home_dir().map(|path| path.join(".ota-plus")))
            .ok_or_else(|| ErrorKind::IllegalArgument("Missing `path`.".into()))?;

        match matches.subcommand() {
            ("init", Some(sub)) => cmd_init(cache, sub),
            ("keygen", Some(sub)) => cmd_keygen(cache, sub),
            ("tuf", Some(sub)) => match sub.subcommand() {
                ("pushkey", Some(sub)) => cmd_tuf_pushkey(cache, sub),
                ("root", Some(sub)) => match sub.subcommand() {
                    ("parse", Some(sub)) => cmd_tuf_root_parse(cache, sub),
                    ("add", Some(sub)) => cmd_tuf_root_add(cache, sub),
                    ("remove", Some(sub)) => cmd_tuf_root_remove(cache, sub),
                    ("sign", _) => cmd_tuf_root_sign(cache),
                    ("push", _) => cmd_tuf_root_push(cache),
                    _ => unreachable!()
                },
                ("targets", Some(sub)) => match sub.subcommand() {
                    ("init", Some(sub)) => cmd_tuf_targets_init(cache, sub),
                    ("add", Some(sub)) => cmd_tuf_targets_add(cache, sub),
                    ("remove", Some(sub)) => cmd_tuf_targets_remove(cache, sub),
                    ("sign", _) => cmd_tuf_targets_sign(cache),
                    ("push", _) => cmd_tuf_targets_push(cache),
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
            Arg::with_name("cache")
                .help("The path of the local cache. Defaults to `~/.ota-plus`.")
                .long("cache")
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
            Arg::with_name("tuf_url")
                .long("tuf-url")
                .takes_value(true)
                .default_value("https://app.atsgarage.com")
                .required(true)
        )
        .arg(
            Arg::with_name("token_url")
                .long("token-url")
                .takes_value(true)
                .default_value("https://auth-plus.atsgarage.com")
                .required(true)
        )
}

fn subcmd_keygen<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name("keygen")
        .about("Generate private keys and print them as PKCS#8v2 DER to STDOUT")
        .arg(arg_role())
        .arg(arg_type())
}

fn subcmd_tuf<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name("tuf")
        .about("Interact with a TUF repository")
        .settings(&[AppSettings::SubcommandRequiredElseHelp])
        .subcommand(
            SubCommand::with_name("pushkey")
                .about("Push a new public key to the remote TUF repo")
                .arg(arg_role())
        )
        .subcommand(subsubcmd_root())
        .subcommand(subsubcmd_targets())
}

fn subsubcmd_root<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name("root")
        .about("Manipulate metadata for the `root` role")
        .settings(&[AppSettings::SubcommandRequiredElseHelp])
        .subcommand(
            SubCommand::with_name("parse")
                .about("Parse an existing root.json")
                .arg(arg_path())
        )
        .subcommand(
            SubCommand::with_name("add")
                .about("Add a key to the root metadata")
                .arg(arg_role())
                .arg(arg_keyid())
                .arg(arg_type())
                .arg(
                    Arg::with_name("pem_file")
                        .help("Path to the PEM encoded public key")
                        .short("p")
                        .long("pem-file")
                        .required(true)
                        .takes_value(true)
                        .validator(is_pem_public)
                )
        )
        .subcommand(
            SubCommand::with_name("remove")
                .about("Remove a key from the root metadata")
                .arg(arg_role())
                .arg(arg_keyid())
        )
        .subcommand(
            SubCommand::with_name("sign")
                .about("Sign the root metadata")
        )
        .subcommand(
            SubCommand::with_name("push")
                .about("Push the signed root metadata to the TUF repo")
        )
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
                .arg(arg_path())
                .arg(
                    Arg::with_name("name")
                        .help("The target name")
                        .short("n")
                        .long("name")
                        .required(true)
                        .takes_value(true)
                )
                .arg(
                    Arg::with_name("version")
                        .help("The target version")
                        .short("v")
                        .long("version")
                        .required(true)
                        .takes_value(true)
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
                .arg(
                    Arg::with_name("force")
                        .help("Add the target even it already exists")
                        .short("f")
                        .long("force"),
                )
        )
        .subcommand(
            SubCommand::with_name("remove")
                .about("Remove a target from the staged metadata")
                .arg(arg_path())
        )
        .subcommand(
            SubCommand::with_name("sign")
                .about("Sign the targets metadata")
        )
        .subcommand(
            SubCommand::with_name("push")
                .about("Push the signed targets metadata to the TUF repo")
        )
}


fn arg_keyid<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("keyid")
        .help("The key ID")
        .short("i")
        .long("keyid")
        .required(true)
        .takes_value(true)
        .validator(is_key_id)
}

fn arg_role<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("role")
        .short("r")
        .long("role")
        .takes_value(true)
        .required(true)
        .possible_values(&["root", "targets", "timestamp", "snapshot"])
}

fn arg_path<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("path")
        .help("The target path")
        .short("p")
        .long("path")
        .required(true)
        .takes_value(true)
        .validator(is_target_path)
}

fn arg_type<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("type")
        .short("t")
        .long("type")
        .takes_value(true)
        .required(true)
        // FIXME(PRO-3849): bouncy castle ed25519 key parsing
        .possible_values(&["rsa"])
}


fn is_key_id(s: String) -> ::std::result::Result<(), String> {
    HEXLOWER.decode(s.as_bytes())
        .map_err(|_| format!("Key ID not hex: {}", s))
        .and_then(|_| if s.len() != 64 { Err("Key ID should be 64 hex chars".into()) } else { Ok(()) })
}

fn is_pem_public(s: String) -> ::std::result::Result<(), String> {
    let mut file = File::open(s).map_err(|e| format!("error opening pem file: {}", e))?;
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(|e| format!("error reading pem file: {}", e))?;
    pem::parse(text).map(|_| ()).map_err(|e| format!("invalid pem key: {}", e))
}

fn is_positive_u64(s: String) -> ::std::result::Result<(), String> {
    s.parse::<u64>().map(|_| ()).map_err(|e| format!("invalid u64: {}", e))
}

fn is_natural_u32(s: String) -> ::std::result::Result<(), String> {
    s.parse::<u32>()
        .map_err(|e| format!("invalid u32: {}", e))
        .and_then(|x| if x < 1 { Err("Version cannot be less than 1".into()) } else { Ok(()) })
}

fn is_datetime(s: String) -> ::std::result::Result<(), String> {
    Utc.datetime_from_str(&s, "%FT%TZ").map(|_| ()).map_err(|e| format!("invalid date: {:?}", e))
}

fn is_target_path(s: String) -> ::std::result::Result<(), String> {
    TargetPath::new(s).map(|_| ()).map_err(|e| format!("invalid target path: {}", e))
}


fn cmd_init(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let client_id = matches.value_of("client_id").unwrap().parse().unwrap();
    let client_secret = matches.value_of("client_secret").unwrap();
    let tuf_url = matches.value_of("tuf_url").unwrap();
    let token_url = matches.value_of("token_url").unwrap();
    let app_conf = AppConfig::new(InterchangeType::Json, tuf_url.into());
    let auth_conf = AuthConfig::new(client_id, client_secret.into(), token_url.into());
    Ok(Cache::new(cache_path, Config::new(app_conf, auth_conf)).map(|_| ())?)
}

fn cmd_keygen(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let cache = get_cache(cache_path)?;
    let role = matches.value_of("role").unwrap().parse::<Role>().unwrap();
    let typ = KeyType::from_str(&matches.value_of("type").unwrap())?;
    let key = KeyPair::new(typ)?;
    Ok(cache.add_key(&key, role)?)
}

fn cmd_tuf_pushkey(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let cache = get_cache(cache_path)?;
    let role = matches.value_of("role").unwrap().parse::<Role>().unwrap();
    let key = cache.get_key(role)?;
    let resp = Http::new(cache.config())?
        .put(&format!("{}/keys/{}", cache.config().app().tuf_url(), role))?
        .json(&PublicKey::from_pubkey(KeyType::Rsa, key.pub_key())?)?
        .send()?;
    check_status(resp)
}

fn cmd_tuf_root_parse(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let cache = get_cache(cache_path)?;
    let path = matches.value_of("path").unwrap();
    let force = matches.is_present("force");
    let file = File::open(path).chain_err(|| "unable to open file")?;
    let signed: SignedMetadata<Json, RootMetadata> = json::from_reader(file)
        .chain_err(|| "unable to parse root.json")?;
    let root: RootMetadata = json::from_value(signed.signed().clone())
        .chain_err(|| "unable to parse root metadata")?;
    Ok(cache.set_unsigned_root(&root, force)?)
}

fn cmd_tuf_root_add(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let cache = get_cache(cache_path)?;
    let mut root = cache.get_unsigned_root().chain_err(|| "unable to open root.json")?;
    let role = matches.value_of("role").unwrap().parse::<Role>().unwrap();
    let keyid = KeyId::from_string(matches.value_of("keyid").unwrap()).unwrap();
    let typ = KeyType::from_str(&matches.value_of("type").unwrap())?;
    let pubkey = PublicKey::from_file(typ, matches.value_of("pem_file").unwrap())?;
    root.add_key(role, keyid, pubkey)?;
    Ok(cache.set_unsigned_root(&root, true)?)
}

fn cmd_tuf_root_remove(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let cache = get_cache(cache_path)?;
    let mut root = cache.get_unsigned_root().chain_err(|| "unable to open root.json")?;
    let role = matches.value_of("role").unwrap().parse::<Role>().unwrap();
    let keyid = KeyId::from_string(matches.value_of("keyid").unwrap()).unwrap();
    root.remove_key(role, &keyid)?;
    Ok(cache.set_unsigned_root(&root, true)?)
}

fn cmd_tuf_root_sign(cache_path: PathBuf) -> Result<()> {
    let cache = get_cache(cache_path)?;
    let root = cache.get_unsigned_root().chain_err(|| "unable to open root.json")?;
    let key = cache.get_key(Role::Root)?;
    let signed: SignedMetadata<Json, RootMetadata> = SignedMetadata::from(&root, &key)?;
    Ok(cache.set_signed_root(&signed, true)?)
}

fn cmd_tuf_root_push(cache_path: PathBuf) -> Result<()> {
    let cache = get_cache(cache_path)?;
    let resp = Http::new(cache.config())?
        .post(&format!("{}/root", cache.config().app().tuf_url()))?
        .json(&cache.get_signed_root::<Json>()?)?
        .send()?;
    check_status(resp)
}

fn cmd_tuf_targets_init(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let version = matches.value_of("version").unwrap().parse::<u32>().unwrap();
    let expires = matches.value_of("expires").unwrap();
    let expires = Utc.datetime_from_str(expires, "%FT%TZ").unwrap();
    let force = matches.is_present("force");
    let cache = get_cache(cache_path)?;
    let targets = TargetsMetadata::new(version, expires, HashMap::new())
        .chain_err(|| "Couldn't create `targets` metadata")?;
    Ok(cache.set_unsigned_targets(&targets, force)?)
}

fn cmd_tuf_targets_add(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let path = TargetPath::new(matches.value_of("path").unwrap().into()).unwrap();
    let name = matches.value_of("name").unwrap();
    let version = matches.value_of("version").unwrap();
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
    let custom = TargetCustom::new(name.into(), version.into(), Some(url.into()), ids);

    let cache = get_cache(cache_path)?;
    let description = TargetDescription::new(length, hashes, Some(custom))?;
    let mut targets = cache.get_unsigned_targets()?;
    if targets.targets().contains_key(&path) && !force {
        bail!(ErrorKind::Runtime("Target already exists".into()))
    }
    targets.add_target(path, description);
    Ok(cache.set_unsigned_targets(&targets, true)?)
}

fn cmd_tuf_targets_remove(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let cache = get_cache(cache_path)?;
    let target = TargetPath::new(matches.value_of("path").unwrap().into()).unwrap();
    let mut targets = cache.get_unsigned_targets()?;
    targets.remove_target(&target);
    Ok(cache.set_unsigned_targets(&targets, true)?)
}

fn cmd_tuf_targets_sign(cache_path: PathBuf) -> Result<()> {
    let cache = get_cache(cache_path)?;
    let key = cache.get_key(Role::Targets)?;
    let targets = cache.get_unsigned_targets()?;
    let signed: SignedMetadata<Json, TargetsMetadata> = SignedMetadata::from(&targets, &key)?;
    Ok(cache.set_signed_targets(&signed, true)?)
}

fn cmd_tuf_targets_push(cache_path: PathBuf) -> Result<()> {
    let cache = get_cache(cache_path)?;
    let resp = Http::new(cache.config())?
        .put(&format!("{}/targets", cache.config().app().tuf_url()))?
        .json(&cache.get_signed_targets::<Json>()?)?
        .send()?;
    check_status(resp)
}


fn get_cache(cache_path: PathBuf) -> Result<Cache> {
    Cache::try_from(cache_path).chain_err(|| "Could not initialize the cache")
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
