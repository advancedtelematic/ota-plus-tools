use chrono;
use data_encoding;
use derp;
use json;
use std::io;
use tempfile;
use toml;

error_chain! {
    foreign_links {
        ChronoParse(chrono::ParseError);
        DataEncoding(data_encoding::DecodeError);
        Der(derp::Error);
        Io(io::Error);
        Json(json::Error);
        TempfilePersist(tempfile::PersistError);
        TomlDeserialize(toml::de::Error);
        TomlSerialize(toml::ser::Error);
    }

    errors {
        Crypto(s: String) {
            description("A cryptographic operation failed")
            display("{}", s)
        }
        Encoding(s: String) {
            description("Data could not be en/decoded")
            display("{}", s)
        }
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
