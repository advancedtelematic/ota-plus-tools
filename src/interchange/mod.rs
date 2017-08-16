//! Structures and functions to aid in various TUF data interchange formats.

mod cjson;

use json;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::fmt::Debug;
use std::io::{Read, Write};

use error::Result;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum InterchangeType {
    #[serde(rename = "json")]
    Json,
}

impl InterchangeType {
    pub fn extension(&self) -> &'static str {
        match *self {
            InterchangeType::Json => "json",
        }
    }
}

/// The format used for data interchange, serialization, and deserialization.
pub trait DataInterchange: Debug + PartialEq + Clone {
    /// The type of data that is contained in the `signed` portion of metadata.
    type RawData: Serialize + DeserializeOwned + Clone + PartialEq;

    fn typ() -> InterchangeType;

    /// The data interchange's extension.
    fn extension() -> &'static str;

    /// A function that canonicalizes data to allow for deterministic signatures.
    fn canonicalize(raw_data: &Self::RawData) -> Result<Vec<u8>>;

    /// Deserialize from `RawData`.
    fn deserialize<T>(raw_data: &Self::RawData) -> Result<T>
    where
        T: DeserializeOwned;

    /// Serialize into `RawData`.
    fn serialize<T>(data: &T) -> Result<Self::RawData>
    where
        T: Serialize;

    /// Write a struct to a stream.
    ///
    /// Note: This *MUST* write the bytes canonically for hashes to line up correctly in other
    /// areas of the library.
    fn to_writer<W, T: Sized>(writer: W, value: &T) -> Result<()>
    where
        W: Write,
        T: Serialize;

    /// Read a struct from a stream.
    fn from_reader<R, T>(rdr: R) -> Result<T>
    where
        R: Read,
        T: DeserializeOwned;
}

/// JSON data interchange.
#[derive(Debug, Clone, PartialEq)]
pub struct Json {}
impl DataInterchange for Json {
    type RawData = json::Value;

    /// ```
    /// use ota_plus::interchange::{DataInterchange, Json};
    ///
    /// assert_eq!(Json::extension(), "json");
    /// ```
    fn extension() -> &'static str {
        "json"
    }

    fn typ() -> InterchangeType {
        InterchangeType::Json
    }

    /// ```
    /// use ota_plus::interchange::{DataInterchange, Json};
    /// use std::collections::HashMap;
    ///
    /// let jsn: &[u8] = br#"{"foo": "bar", "baz": "quux"}"#;
    /// let raw = Json::from_reader(jsn).unwrap();
    /// let out = Json::canonicalize(&raw).unwrap();
    /// assert_eq!(out, br#"{"baz":"quux","foo":"bar"}"#);
    /// ```
    fn canonicalize(raw_data: &Self::RawData) -> Result<Vec<u8>> {
        cjson::canonicalize(raw_data)
    }

    /// ```
    /// extern crate ota_plus;
    /// #[macro_use]
    /// extern crate serde_derive;
    /// #[macro_use]
    /// extern crate serde_json;
    ///
    /// use ota_plus::interchange::{DataInterchange, Json};
    /// use std::collections::HashMap;
    ///
    /// #[derive(Deserialize, Debug, PartialEq)]
    /// struct Thing {
    ///    foo: String,
    ///    bar: String,
    /// }
    ///
    /// fn main() {
    ///     let jsn = json!({"foo": "wat", "bar": "lol"});
    ///     let thing = Thing { foo: "wat".into(), bar: "lol".into() };
    ///     let de: Thing = Json::deserialize(&jsn).unwrap();
    ///     assert_eq!(de, thing);
    /// }
    /// ```
    fn deserialize<T>(raw_data: &Self::RawData) -> Result<T>
    where
        T: DeserializeOwned,
    {
        Ok(json::from_value(raw_data.clone())?)
    }

    /// ```
    /// extern crate ota_plus;
    /// #[macro_use]
    /// extern crate serde_derive;
    /// #[macro_use]
    /// extern crate serde_json;
    ///
    /// use ota_plus::interchange::{DataInterchange, Json};
    /// use std::collections::HashMap;
    ///
    /// #[derive(Serialize)]
    /// struct Thing {
    ///    foo: String,
    ///    bar: String,
    /// }
    ///
    /// fn main() {
    ///     let jsn = json!({"foo": "wat", "bar": "lol"});
    ///     let thing = Thing { foo: "wat".into(), bar: "lol".into() };
    ///     let se: serde_json::Value = Json::serialize(&thing).unwrap();
    ///     assert_eq!(se, jsn);
    /// }
    /// ```
    fn serialize<T>(data: &T) -> Result<Self::RawData>
    where
        T: Serialize,
    {
        Ok(json::to_value(data)?)
    }

    /// ```
    /// use ota_plus::interchange::{DataInterchange, Json};
    ///
    /// let arr = vec![1, 2, 3];
    /// let mut buf = Vec::new();
    /// Json::to_writer(&mut buf, &arr).unwrap();
    /// assert!(&buf == b"[1, 2, 3]" || &buf == b"[1,2,3]");
    /// ```
    fn to_writer<W, T: Sized>(mut writer: W, value: &T) -> Result<()>
    where
        W: Write,
        T: Serialize,
    {
        let bytes = Self::canonicalize(&Self::serialize(value)?)?;
        writer.write_all(&bytes)?;
        Ok(())
    }

    /// ```
    /// use ota_plus::interchange::{DataInterchange, Json};
    /// use std::collections::HashMap;
    ///
    /// let jsn: &[u8] = br#"{"foo": "bar", "baz": "quux"}"#;
    /// let _: HashMap<String, String> = Json::from_reader(jsn).unwrap();
    /// ```
    fn from_reader<R, T>(rdr: R) -> Result<T>
    where
        R: Read,
        T: DeserializeOwned,
    {
        Ok(json::from_reader(rdr)?)
    }
}
