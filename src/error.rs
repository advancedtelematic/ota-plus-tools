use std::io;
use toml;

error_chain! {
    foreign_links {
        Io(io::Error);
        TomlDeserialize(toml::de::Error);
        TomlSerialize(toml::ser::Error);
    }

    errors {
        IllegalArgument(s: String) {
            description("An illegal argument was supplied")
            display("Illegal argument: {}", s)
        }
        Crypto(s: String) {
            description("A cryptographic operation failed")
            display("{}", s)
        }
    }
}
