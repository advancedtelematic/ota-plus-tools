//! Errors, helpers, and converters.

use chrono;
use data_encoding;
use derp;
use json;
use pem;
use reqwest;
use std;
use tempfile;
use toml;

error_chain! {
    foreign_links {
        ChronoParse(chrono::ParseError);
        DataEncoding(data_encoding::DecodeError);
        Der(derp::Error);
        Http(reqwest::Error);
        Io(std::io::Error);
        Json(json::Error);
        Pem(pem::Error);
        TempfilePersist(tempfile::PersistError);
        TomlDeserialize(toml::de::Error);
        TomlSerialize(toml::ser::Error);
        Utf8(std::string::FromUtf8Error);
    }

    errors {
        /// There was a failure with a cryptographic operation.
        Crypto(s: String) {
            description("A cryptographic operation failed")
            display("{}", s)
        }
        /// Data could not be en/decoded.
        Encoding(s: String) {
            description("Data could not be en/decoded")
            display("{}", s)
        }
        /// An illegal argument was supplied to a function.
        IllegalArgument(s: String) {
            description("An illegal argument was supplied")
            display("Illegal argument: {}", s)
        }
        /// An unexpected runtime error.
        Runtime(s: String) {
            description("A runtime error occurred")
            display("{}", s)
        }
    }
}
