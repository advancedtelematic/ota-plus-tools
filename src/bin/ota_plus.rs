extern crate chrono;
extern crate clap;
extern crate data_encoding;
#[macro_use]
extern crate error_chain;
extern crate futures;
extern crate hyper;
extern crate ota_plus;
extern crate serde_json as json;
extern crate tokio_core;

use chrono::offset::Utc;
use chrono::prelude::*;
use clap::{App, ArgMatches, AppSettings, SubCommand, Arg};
use data_encoding::{BASE64, HEXLOWER};
use futures::future::Future;
use hyper::{Client, Method, Uri, Request, StatusCode};
use ota_plus::cache::Cache;
use ota_plus::config::{Config, AppConfig, AuthConfig};
use ota_plus::crypto::{KeyType, KeyPair, HashAlgorithm, HashValue};
use ota_plus::interchange::{InterchangeType, Json};
use ota_plus::tuf::{TargetsMetadata, TargetPath, TargetDescription};
use std::collections::HashMap;
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::str::FromStr;
use tokio_core::reactor::Core;

error_chain! {
    foreign_links {
        Io(io::Error);
        Json(json::Error);
        DataEncodingDecode(data_encoding::DecodeError);
        Hyper(hyper::Error);
        HyperUri(hyper::error::UriError);
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
    let home: Result<_> = matches
        .value_of("home")
        .map(PathBuf::from)
        .or_else(|| env::home_dir().map(|p| p.join(".ota-plus")))
        .ok_or_else(|| {
            ErrorKind::IllegalArgument("Missing `path`.".into()).into()
        });
    // this looks dumb, but the compiler requires it
    let home = home?;

    if let Some(_) = matches.subcommand_matches("init") {
        cmd_init(home)
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
                cmd_targets_init(home, version, expires, force)
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
                    cmd_targets_target_add(home, target, force, length, sha256, sha512, encoding)
                } else if let Some(matches) = matches.subcommand_matches("remove") {
                    let target = TargetPath::new(matches.value_of("target").unwrap().into())
                        .unwrap();
                    cmd_targets_target_remove(home, &target)
                } else if let Some(_) = matches.subcommand_matches("push") {
                    cmd_targets_push(home)
                } else if let Some(_) = matches.subcommand_matches("sign") {
                    cmd_targets_sign(home)
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
            Arg::with_name("home")
                .help(
                    "The path to the settings and local cache. Defaults to `~/.ota-plus`.",
                )
                .short("H")
                .long("home")
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
                ),
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
        .subcommand(SubCommand::with_name("push").about(
            "Push the signed metadata to the remote repo",
        ))
        .subcommand(SubCommand::with_name("sign").about(
            "Signed the metadata",
        ))

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
    let mut client_id = String::new();
    loop {
        print!("Enter your client id: ");
        io::stdin().read_line(&mut client_id)?;
        println!("");

        if let Some(_) = client_id.pop() {
            if !client_id.is_empty() {
                break;
            }
        }
    }

    let mut client_secret = String::new();
    loop {
        print!("Enter your client secret: ");
        io::stdin().read_line(&mut client_secret)?;
        println!("");

        if let Some(_) = client_secret.pop() {
            if !client_secret.is_empty() {
                break;
            }
        }
    }

    let mut repo_id = String::new();
    loop {
        print!("Enter your repo ID: ");
        io::stdin().read_line(&mut repo_id)?;
        println!("");

        if let Some(_) = repo_id.pop() {
            if !repo_id.is_empty() {
                break;
            }
        }
    }

    let config = Config::new(
        AppConfig::new(InterchangeType::Json, "https://atsgarage.com".into()),
        AuthConfig::new(client_id, client_secret, repo_id),
    );

    Cache::new(path, config).map(|_| ()).map_err(|e| e.into())
}

fn cmd_targets_init(
    path: PathBuf,
    version: u32,
    expires: DateTime<Utc>,
    force: bool,
) -> Result<()> {
    let cache = get_cache(path)?;
    let targets = TargetsMetadata::new(version, expires, HashMap::new())
        .chain_err(|| "Couldn't create `targets` metadata")?;
    cache.set_unsigned_targets(&targets, force).map_err(
        |e| e.into(),
    )
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

    if let Some(s) = sha256 {
        let _ = hashes.insert(HashAlgorithm::Sha256, HashValue::new(encoding.decode(s)?));
    };

    if let Some(s) = sha512 {
        let _ = hashes.insert(HashAlgorithm::Sha512, HashValue::new(encoding.decode(s)?));
    };

    let description = TargetDescription::new(length, hashes)?;
    let mut targets = cache.load_targets()?;

    if targets.targets().contains_key(&target) && !force {
        bail!(ErrorKind::Runtime("Target already exists".into()))
    }
    targets.add_target(target, description);
    cache.set_unsigned_targets(&targets, true)?;
    Ok(())
}

fn cmd_targets_target_remove(path: PathBuf, target: &TargetPath) -> Result<()> {
    let cache = get_cache(path)?;
    let mut targets = cache.load_targets()?;
    targets.remove_target(target);
    cache.set_unsigned_targets(&targets, true)?;
    Ok(())
}

fn cmd_targets_push(path: PathBuf) -> Result<()> {
    let cache = get_cache(path)?;
    let core = Core::new()?;
    let client = Client::new(&core.handle());

    let uri = Uri::from_str(&format!("{}/repo/{}/targets", cache.config().app().uri(), cache.config().auth().repo_id()))?;

    let mut request = Request::new(Method::Put, uri);
    // TODO this defaults to JSON
    request.set_body(json::to_string(&cache.signed_targets::<Json>()?)?);

    let resp = client.request(request).wait()?;
    if resp.status() != StatusCode::Ok {
        bail!(ErrorKind::Runtime(
            format!("Bad status code: {:?}", resp.status()),
        ));
    }
    Ok(())
}

fn cmd_targets_sign(path: PathBuf) -> Result<()> {
    let cache = get_cache(path)?;
    panic!() // TODO
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_parser() {
        let _ = parser();
    }
}
