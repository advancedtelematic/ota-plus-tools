extern crate chrono;
extern crate clap;
extern crate data_encoding;
extern crate env_logger;
#[macro_use]
extern crate error_chain;
extern crate ota_plus;
extern crate serde_json as json;
#[cfg(test)]
extern crate tempdir;
extern crate reqwest;

use chrono::offset::Utc;
use chrono::prelude::*;
use clap::{App, ArgMatches, AppSettings, SubCommand, Arg};
use data_encoding::{BASE64, HEXLOWER};
use ota_plus::cache::Cache;
use ota_plus::config::{Config, AppConfig, AuthConfig};
use ota_plus::crypto::{KeyId, KeyPair, KeyType, HashAlgorithm, HashValue};
use ota_plus::http::Http;
use ota_plus::interchange::{InterchangeType, Json};
use ota_plus::tuf::{PrivateKey, PublicKey, Role, RootMetadata, SignedMetadata, TargetsMetadata,
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
    match run_main(parser().get_matches()) {
        Ok(()) => (),
        Err(e) => {
            // TODO pretty print the error
            writeln!(&mut io::stderr(), "{:?}", e).unwrap();
            std::process::exit(1);
        }
    }
}

fn run_main(matches: ArgMatches) -> Result<()> {
    let cache = matches
        .value_of("cache")
        .map(PathBuf::from)
        .or_else(|| env::home_dir().map(|path| path.join(".ota-plus")))
        .ok_or_else(|| ErrorKind::IllegalArgument("Missing `path`.".into()))?;

    match matches.subcommand() {
        ("init", Some(sub)) => cmd_init(cache, sub),
        ("tuf", Some(sub)) => {
            match sub.subcommand() {
                ("key", Some(sub)) => {
                    match sub.subcommand() {
                        ("gen", Some(sub)) => cmd_tuf_key_gen(cache, sub),
                        ("push", Some(sub)) => cmd_tuf_key_push(cache, sub),
                        _ => unreachable!(),
                    }
                }
                ("root", Some(sub)) => {
                    match sub.subcommand() {
                        ("init", Some(sub)) => cmd_tuf_root_init(cache, sub),
                        ("import", Some(sub)) => cmd_tuf_root_import(cache, sub),
                        ("add", Some(sub)) => cmd_tuf_root_add(cache, sub),
                        ("remove", Some(sub)) => cmd_tuf_root_remove(cache, sub),
                        ("sign", Some(sub)) => cmd_tuf_root_sign(cache, sub),
                        ("push", _) => cmd_tuf_root_push(cache),
                        _ => unreachable!(),
                    }
                }
                ("targets", Some(sub)) => {
                    match sub.subcommand() {
                        ("init", Some(sub)) => cmd_tuf_targets_init(cache, sub),
                        ("add", Some(sub)) => cmd_tuf_targets_add(cache, sub),
                        ("remove", Some(sub)) => cmd_tuf_targets_remove(cache, sub),
                        ("sign", Some(sub)) => cmd_tuf_targets_sign(cache, sub),
                        ("push", _) => cmd_tuf_targets_push(cache),
                        _ => unreachable!(),
                    }
                }
                ("rotate-root-to-offline-key", Some(sub)) => cmd_tuf_rotate(cache, sub),
                _ => unreachable!(),
            }
        }
        _ => unreachable!(),
    }
}

fn parser<'a, 'b>() -> App<'a, 'b> {
    App::new("ota-plus")
        .version(env!("CARGO_PKG_VERSION"))
        .about("CLI tool for interacting with OTA+")
        .settings(&[AppSettings::SubcommandRequiredElseHelp])
        .arg(
            Arg::with_name("cache")
                // TODO use #[cfg(...)] to change this to say `C:\\$user\.ota-plus` or whatever it
                // is on windows
                .help("The path of the local cache. Defaults to `~/.ota-plus`.")
                .long("cache")
                .takes_value(true),
        )
        .subcommand(subcmd_init())
        .subcommand(subcmd_tuf())
}

fn subcmd_init<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name("init")
        .about("Initialize the local cache")
        .arg(
            Arg::with_name("client_id")
                .long("client-id")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("client_secret")
                .long("client-secret")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("tuf_url")
                .long("tuf-url")
                .takes_value(true)
                .default_value("https://app.atsgarage.com")
                .required(true),
        )
        .arg(
            Arg::with_name("token_url")
                .long("token-url")
                .takes_value(true)
                .default_value("https://auth-plus.atsgarage.com")
                .required(true),
        )
}

fn subcmd_tuf<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name("tuf")
        .about("Interact with a TUF repository")
        .settings(&[AppSettings::SubcommandRequiredElseHelp])
        .subcommand(subsubcmd_root())
        .subcommand(subsubcmd_targets())
        .subcommand(subsubcmd_key())
        .subcommand(
            SubCommand::with_name("rotate-root-to-offline-key")
                .about("Rotate the root metadata to offline mode. WARNING: May break you account.")
                .settings(&[AppSettings::ArgRequiredElseHelp])
                .arg(
                    Arg::with_name("new_root_key_name")
                        .help("The name of the new root key to be used for the new root metadata")
                        .long("new-root-key-name")
                        .takes_value(true)
                        .required(true)
                )
                .arg(
                    Arg::with_name("new_targets_key_name")
                        .help("The name of the new targets key to be used for the new targets metadata")
                        .long("new-targets-key-name")
                        .takes_value(true)
                        .required(true)
                )
                .arg(
                    Arg::with_name("previous_key_alias")
                        .help("The name of the old root (used for saving after download")
                        .long("previous-key-alias")
                        .takes_value(true)
                        .required(true)
                )
        )
}

fn subsubcmd_key<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name("key")
        .about("Manage TUF signing keys")
        .settings(&[AppSettings::SubcommandRequiredElseHelp])
        .subcommand(
            SubCommand::with_name("gen")
                .about("Generate private keys as PKCS#8v2 DER")
                .arg(arg_name())
                .arg(arg_type()),
        )
        .subcommand(
            SubCommand::with_name("push")
                .about("Push a new public key to the remote TUF repo")
                .arg(arg_name())
                .arg(arg_role()),
        )
}

fn subsubcmd_root<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name("root")
        .about("Manipulate metadata for the `root` role")
        .settings(&[AppSettings::SubcommandRequiredElseHelp])
        .subcommand(
            SubCommand::with_name("import")
                .about("Import an existing root.json")
                .arg(arg_path()),
        )
        .subcommand(
            SubCommand::with_name("add")
                .about("Add a key to the root metadata")
                .arg(arg_role())
                .arg(
                    Arg::with_name("path")
                        .help("Path to the public key")
                        .short("p")
                        .long("path")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("remove")
                .about("Remove a key from the root metadata")
                .arg(arg_role())
                .arg(arg_key_id()),
        )
        .subcommand(SubCommand::with_name("sign").about(
            "Sign the root metadata",
        ))
        .subcommand(SubCommand::with_name("push").about(
            "Push the signed root metadata to the TUF repo",
        ))
        .subcommand(
            SubCommand::with_name("init")
                .about("Create new, blank root metadata")
                .arg(
                    Arg::with_name("version")
                        .help("The initial root version")
                        .short("v")
                        .long("version")
                        .takes_value(true)
                        .required(true)
                        .validator(is_natural_u32),
                )
                .arg(
                    Arg::with_name("consistent_snapshot")
                        .help("Set the `consistent_snapshot` flag to true")
                        .long("consistent-snapshot"),
                )
                .arg(
                    Arg::with_name("expires")
                        .help("Set the metadata's expiration date")
                        .short("e")
                        .long("expires")
                        .required(true)
                        .takes_value(true)
                        .validator(is_datetime),
                )
                .arg(
                    Arg::with_name("force")
                        .help("Create the `root` metadata even it already exists")
                        .short("f")
                        .long("force"),
                ),
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
                .arg(
                    Arg::with_name("name")
                        .help("The target name")
                        .short("n")
                        .long("name")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("version")
                        .help("The target version")
                        .short("v")
                        .long("version")
                        .required(true)
                        .takes_value(true),
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
                        .required(true),
                )
                .arg(
                    Arg::with_name("encoding")
                        .help("The encoding used for the hashes")
                        .default_value("hexlower")
                        .possible_values(&["hexlower", "base64"]),
                )
                .arg(
                    Arg::with_name("sha256")
                        .help("The SHA256 hash of the target")
                        .long("sha256")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("sha512")
                        .help("The SHA512 hash of the target")
                        .long("sha512")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("hardware_id")
                        .help("Restrict the target to specific hardware IDs")
                        .long("hardware-id")
                        .takes_value(true)
                        .multiple(true),
                )
                .arg(
                    Arg::with_name("release_counter")
                        .help("The Uptane release counter for the target")
                        .long("release-counter")
                        .takes_value(true)
                        .required(true)
                        .validator(is_natural_u32),
                )
                .arg(
                    Arg::with_name("force")
                        .help("Add the target even it already exists")
                        .short("f")
                        .long("force"),
                ),
        )
        .subcommand(
            SubCommand::with_name("remove")
                .about("Remove a target from the staged metadata")
                .arg(arg_path()),
        )
        .subcommand(
            SubCommand::with_name("sign")
                .about("Sign the targets metadata")
                .arg(
                    Arg::with_name("key_name")
                        .long("key-name")
                        .help("The name of the key used for signing")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .subcommand(SubCommand::with_name("push").about(
            "Push the signed targets metadata to the TUF repo",
        ))
}

fn arg_name<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("name")
        .short("n")
        .long("name")
        .required(true)
        .takes_value(true)
}

fn arg_key_id<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("key_id")
        .help("The key ID")
        .short("i")
        .long("key-id")
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
        .possible_values(&["ed25519", "rsa"])
        .default_value("ed25519")
}


fn is_key_id(s: String) -> ::std::result::Result<(), String> {
    HEXLOWER
        .decode(s.as_bytes())
        .map_err(|_| format!("Key ID not hex: {}", s))
        .and_then(|_| if s.len() != 64 {
            Err("Key ID should be 64 hex chars".into())
        } else {
            Ok(())
        })
}

fn is_positive_u64(s: String) -> ::std::result::Result<(), String> {
    s.parse::<u64>().map(|_| ()).map_err(|e| {
        format!("invalid u64: {}", e)
    })
}

fn is_natural_u32(s: String) -> ::std::result::Result<(), String> {
    s.parse::<u32>()
        .map_err(|e| format!("invalid u32: {}", e))
        .and_then(|x| if x < 1 {
            Err("Version cannot be less than 1".into())
        } else {
            Ok(())
        })
}

fn is_datetime(s: String) -> ::std::result::Result<(), String> {
    Utc.datetime_from_str(&s, "%FT%TZ").map(|_| ()).map_err(
        |e| {
            format!("invalid date {:?} : {:?}", s, e)
        },
    )
}

fn is_target_path(s: String) -> ::std::result::Result<(), String> {
    TargetPath::new(s).map(|_| ()).map_err(|e| {
        format!("invalid target path: {}", e)
    })
}


fn cmd_init(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let client_id = matches.value_of("client_id").unwrap().parse().unwrap();
    let client_secret = matches.value_of("client_secret").unwrap();
    let tuf_url = matches.value_of("tuf_url").unwrap();
    let token_url = matches.value_of("token_url").unwrap();
    let app_conf = AppConfig::new(InterchangeType::Json, tuf_url.into());
    let auth_conf = AuthConfig::new(client_id, client_secret.into(), token_url.into());
    Ok(Cache::new(cache_path, Config::new(app_conf, auth_conf))
        .map(|_| ())?)
}

fn cmd_tuf_key_gen(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let cache = get_cache(cache_path)?;
    let name = matches.value_of("name").unwrap();
    let typ = KeyType::from_str(&matches.value_of("type").unwrap())?;
    let key = KeyPair::new(typ)?;
    Ok(cache.add_key(&key, name)?)
}

fn cmd_tuf_key_push(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let cache = get_cache(cache_path)?;
    let role = matches.value_of("role").unwrap().parse::<Role>().unwrap();
    let key_name = matches.value_of("key_name").unwrap();
    let key = cache.get_key(key_name)?;
    let mut resp = Http::new(cache.config())?
        .put(&format!("{}/keys/{}", cache.config().app().tuf_url(), role))?
        .json(&key.as_public_key()?)?
        .send()?;
    check_status(&mut resp)
}

fn cmd_tuf_root_import(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let cache = get_cache(cache_path)?;
    let path = matches.value_of("path").unwrap();
    let force = matches.is_present("force");
    let file = File::open(path).chain_err(
        || format!("Unable to open file {:?}", path),
    )?;
    // TODO this is hardcoded importing JSON only
    let signed: SignedMetadata<Json, RootMetadata> = json::from_reader(file).chain_err(
        || "unable to parse root.json",
    )?;
    let root: RootMetadata = json::from_value(signed.signed().clone()).chain_err(
        || "unable to parse root metadata",
    )?;
    Ok(cache.set_unsigned_root(&root, force)?)
}

fn cmd_tuf_root_add(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let cache = get_cache(cache_path)?;
    let mut root = cache.get_unsigned_root().chain_err(
        || "unable to open root.json",
    )?;
    let role = matches.value_of("role").unwrap().parse::<Role>().unwrap();
    let key_id = KeyId::from_string(matches.value_of("key_id").unwrap()).unwrap();
    let pubkey = PublicKey::from_file(matches.value_of("path").unwrap())?;
    root.add_key(role, key_id, pubkey)?;
    Ok(cache.set_unsigned_root(&root, true)?)
}

fn cmd_tuf_root_remove(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let cache = get_cache(cache_path)?;
    let mut root = cache.get_unsigned_root().chain_err(
        || "unable to open root.json",
    )?;
    let role = matches.value_of("role").unwrap().parse::<Role>().unwrap();
    let key_id = KeyId::from_string(matches.value_of("key_id").unwrap()).unwrap();
    root.remove_key(role, &key_id)?;
    Ok(cache.set_unsigned_root(&root, true)?)
}

fn cmd_tuf_root_sign(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let cache = get_cache(cache_path)?;
    let root = cache.get_unsigned_root().chain_err(
        || "unable to open root.json",
    )?;
    let key_name = matches.value_of("key").unwrap();
    let key = cache.get_key(key_name).chain_err(|| "no root key found")?;
    let signed: SignedMetadata<Json, RootMetadata> = SignedMetadata::from(&root, &key)?;
    Ok(cache.set_signed_root(&signed, true)?)
}

fn cmd_tuf_root_push(cache_path: PathBuf) -> Result<()> {
    let cache = get_cache(cache_path)?;
    let mut resp = Http::new(cache.config())?
        .post(&format!("{}/root", cache.config().app().tuf_url()))?
        .json(&cache.get_signed_root::<Json>()?)?
        .send()?;
    check_status(&mut resp)
}

fn cmd_tuf_rotate(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let new_root = matches.value_of("new_root_key_name").unwrap();
    let old_root = matches.value_of("previous_key_alias").unwrap();
    let new_targets = matches.value_of("new_targets_key_name").unwrap();

    let cache = get_cache(cache_path)?;

    let new_root = cache.get_key(new_root).chain_err(
        || "no local root key found",
    )?;
    let new_targets = cache.get_key(new_targets).chain_err(
        || "no local targets get found",
    )?;

    let old_meta = Http::new(cache.config())?
        .get(&format!("{}/root", cache.config().app().tuf_url()))?
        .send()?;

    // TODO this is unsafe because we don't know that this root is really what we want
    // we'd need to do some TUF verification on it
    let mut meta: RootMetadata = json::from_reader(old_meta).chain_err(
        || "unable to read current root metadata",
    )?;

    let old_key_id = {
        let role_keys = meta.roles_mut().get_mut(&Role::Root).ok_or_else(|| {
            Error::from_kind(ErrorKind::Runtime("no current root keys".into()))
        })?;
        if role_keys.key_ids().len() != 1 {
            bail!(format!(
                "expected 1 role key ID, found {}",
                role_keys.key_ids().len()
            ));
        }
        let old_key_id = role_keys.key_ids_mut().drain().last().ok_or_else(|| {
            Error::from_kind(ErrorKind::Msg("Missing key id".into()))
        })?;
        role_keys.key_ids_mut().insert(new_root.key_id().clone());
        old_key_id
    };

    // remove old targets key
    {
        let role_keys = meta.roles_mut().get_mut(&Role::Targets).ok_or_else(|| {
            Error::from_kind(ErrorKind::Runtime("no current root keys".into()))
        })?;
        let ids = role_keys.key_ids_mut();
        ids.clear();
        ids.insert(new_targets.key_id().clone());
    }

    let _ = meta.keys_mut().remove(&old_key_id);
    let _ = meta.keys_mut().insert(
        new_root.key_id().clone(),
        new_root.as_public_key()?,
    );

    // WARNING: any errors after calling DELETE will probably screw the user account

    let old_key_id = HEXLOWER.encode(&old_key_id);
    let mut deleted_key = Http::new(cache.config())?
        .delete(&format!(
            "{}/root/private_keys/{}",
            cache.config().app().tuf_url(),
            old_key_id
        ))?
        .send()?;
    check_status(&mut deleted_key)?;

    let old_key: PrivateKey = json::from_reader(deleted_key).chain_err(
        || "failed to parse old root private key as json",
    )?;
    let old_key = old_key.as_key_pair()?;

    cache.add_key(&old_key, old_root)?;

    let mut signed: SignedMetadata<Json, RootMetadata> = SignedMetadata::from(&meta, &new_root)?;

    signed.add_signature(&old_key)?;

    cache.set_signed_root(&signed, true)?;

    let mut resp = Http::new(cache.config())?
        .post(&format!("{}/root", cache.config().app().tuf_url()))?
        .json(&signed)?
        .send()?;
    check_status(&mut resp)
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

// TODO more of this logic should be in the cache and not here
fn cmd_tuf_targets_add(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let name = matches.value_of("name").unwrap();
    let version = matches.value_of("version").unwrap();
    let path = TargetPath::new(format!("{}-{}", name, version))?;
    let length = matches.value_of("length").unwrap().parse::<u64>().unwrap();
    let encoding = Encoding::Hexlower; // TODO parameterize?
    let force = matches.is_present("force");

    let mut hashes = HashMap::new();
    if let Some(s) = matches.value_of("sha256") {
        let _ = hashes.insert(HashAlgorithm::Sha256, HashValue::new(encoding.decode(s)?));
    }
    if let Some(s) = matches.value_of("sha512") {
        let _ = hashes.insert(HashAlgorithm::Sha512, HashValue::new(encoding.decode(s)?));
    }

    let url = matches.value_of("url").unwrap();
    let ids = matches.values_of("hardware_id").map(|ids| {
        ids.map(String::from).collect::<Vec<_>>()
    });
    let release_counter = matches
        .value_of("release_counter")
        .unwrap()
        .parse()
        .unwrap();

    let custom = TargetCustom::new(
        name.into(),
        version.into(),
        Some(url.into()),
        ids,
        release_counter,
    );

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

fn cmd_tuf_targets_sign(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let cache = get_cache(cache_path)?;
    let key_name = matches.value_of("key_name").unwrap();
    let key = cache.get_key(key_name)?;
    let targets = cache.get_unsigned_targets()?;
    let signed: SignedMetadata<Json, TargetsMetadata> = SignedMetadata::from(&targets, &key)?;
    Ok(cache.set_signed_targets(&signed, true)?)
}

fn cmd_tuf_targets_push(cache_path: PathBuf) -> Result<()> {
    let cache = get_cache(cache_path)?;
    let mut resp = Http::new(cache.config())?
        .put(&format!("{}/targets", cache.config().app().tuf_url()))?
        .json(&cache.get_signed_targets::<Json>()?)?
        .send()?;
    check_status(&mut resp)
}

fn cmd_tuf_root_init(cache_path: PathBuf, matches: &ArgMatches) -> Result<()> {
    let version = matches.value_of("version").unwrap().parse().unwrap();
    let consistent_snapshot = matches.is_present("consistent_snapshot");
    let expires = matches.value_of("expires").unwrap();
    let expires = Utc.datetime_from_str(expires, "%FT%TZ").unwrap();
    let force = matches.is_present("force");
    let cache = get_cache(cache_path)?;
    let root = RootMetadata::new(
        version,
        expires,
        HashMap::new(),
        HashMap::new(),
        consistent_snapshot,
    )?;
    cache.set_unsigned_root(&root, force)?;
    Ok(())
}

fn get_cache(cache_path: PathBuf) -> Result<Cache> {
    Cache::try_from(cache_path).chain_err(|| "Could not initialize the cache")
}

fn check_status(resp: &mut Response) -> Result<()> {
    match resp.status() {
        StatusCode::Ok | StatusCode::NoContent => Ok(()),
        status => {
            let mut data = Vec::new();
            // TODO remove unwrap and just return the error
            resp.read_to_end(&mut data).unwrap();
            let body = String::from_utf8_lossy(&data);
            bail!(ErrorKind::Runtime(
                format!("Status: {}, Body:\n{}", status, body),
            ));
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
            _ => Err(
                ErrorKind::IllegalArgument(format!("Unknown encoding: {}", s)).into(),
            ),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::path::Path;
    use tempdir::TempDir;

    fn tmp() -> TempDir {
        TempDir::new("ota-plus").unwrap()
    }

    fn read<P: AsRef<Path>>(path: P) -> Vec<u8> {
        let mut file = File::open(path).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();
        buf
    }

    #[test]
    fn check_parser() {
        let _ = parser();
    }

    fn do_init(tmp: &TempDir) {
        let parser = parser();
        let client_id = "00000000-0000-0000-0000-000000000000";
        let client_secret = "abc123";
        let matches = parser
            .get_matches_from_safe(
                &[
                    "ota-plus",
                    "--cache",
                    &tmp.path().to_string_lossy(),
                    "init",
                    "--client-id",
                    client_id,
                    "--client-secret",
                    client_secret,
                ],
            )
            .unwrap();
        run_main(matches).unwrap();
    }

    #[test]
    fn init() {
        let tmp = tmp();
        do_init(&tmp);
    }


    fn do_gen_key(typ: KeyType, type_str: &str) {
        let tmp = tmp();
        do_init(&tmp);

        let key_name = "foo";
        let parser = parser();
        let matches = parser
            .get_matches_from_safe(
                &[
                    "ota-plus",
                    "--cache",
                    &tmp.path().to_string_lossy(),
                    "tuf",
                    "key",
                    "gen",
                    "--type",
                    type_str,
                    "--name",
                    key_name,
                ],
            )
            .unwrap();
        run_main(matches).unwrap();
        let priv_key = read(tmp.path().join("keys").join(key_name));
        let priv_key = KeyPair::from(priv_key).unwrap();
        assert_eq!(priv_key.typ(), typ);

        let pub_key = read(tmp.path().join("keys").join(format!("{}.pub", key_name)));
        assert_eq!(&*pub_key, &**priv_key.pub_key());
    }

    #[test]
    fn tuf_key_gen_ed25519() {
        do_gen_key(KeyType::Ed25519, "ed25519")
    }

    #[test]
    fn tuf_key_gen_rsa() {
        do_gen_key(KeyType::Rsa, "rsa")
    }

    #[test]
    fn tuf_root_init() {
        let version = 1;
        let expires = Utc.ymd(2017, 1, 1).and_hms(0, 0, 0);
        let expires_str = &format!("{}", expires.format("%FT%TZ"));

        let tmp = tmp();
        do_init(&tmp);
        let parser = parser();
        let matches = parser
            .get_matches_from_safe(
                &[
                    "ota-plus",
                    "--cache",
                    &tmp.path().to_string_lossy(),
                    "tuf",
                    "root",
                    "init",
                    "--expires",
                    expires_str,
                    "--version",
                    &version.to_string(),
                ],
            )
            .unwrap();
        run_main(matches).unwrap();

        let root_path = tmp.path().join("metadata").join("unsigned").join(
            "root.json",
        );
        let root = read(root_path);
        let root: RootMetadata = json::from_slice(&root).unwrap();
        let expected = RootMetadata::new(1, expires, HashMap::new(), HashMap::new(), false)
            .unwrap();
        assert_eq!(root, expected);
    }
}
