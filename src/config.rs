//! Configuration files needed for interacting with OTA+.

use interchange::InterchangeType;
use uuid::Uuid;


/// Configuration for the `ota-plus` CLI and `Cache`.
#[derive(Serialize, Deserialize)]
pub struct Config {
    app: AppConfig,
    auth: AuthConfig,
}

impl Config {
    /// Create a new `Config`.
    pub fn new(app: AppConfig, auth: AuthConfig) -> Self {
        Config { app, auth }
    }

    /// An immutable reference to the `AuthConfig`.
    pub fn auth(&self) -> &AuthConfig {
        &self.auth
    }

    /// An immutable reference to the `AppConfig`.
    pub fn app(&self) -> &AppConfig {
        &self.app
    }
}

/// Configuration for how the app behaves with OTA+.
#[derive(Serialize, Deserialize)]
pub struct AppConfig {
    interchange: InterchangeType,
    tuf_url: String,
}

impl AppConfig {
    /// Create a new `AppConfig`. The interchange determines how TUF metadata is serialized and
    /// deserialized. The `tuf_url` points to the backend.
    pub fn new(interchange: InterchangeType, tuf_url: String) -> Self {
        AppConfig {
            interchange,
            tuf_url,
        }
    }

    /// The config's data interchange type.
    pub fn interchange(&self) -> InterchangeType {
        self.interchange
    }

    /// A reference to the backend's URL string.
    pub fn tuf_url(&self) -> &str {
        &self.tuf_url
    }
}

/// Configuration for how the app does authorization.
#[derive(Serialize, Deserialize)]
pub struct AuthConfig {
    client_id: Uuid,
    client_secret: String,
    token_url: String,
}

impl AuthConfig {
    /// Create a new `AuthConfig`, authenticating with the `client_id` and `client_secret` against
    /// the backend at `token_url`.
    pub fn new(client_id: Uuid, client_secret: String, token_url: String) -> Self {
        AuthConfig {
            client_id,
            client_secret,
            token_url,
        }
    }

    /// An immutable reference to the client_id.
    pub fn client_id(&self) -> &Uuid {
        &self.client_id
    }

    /// An immutable reference to the client_secret.
    pub fn client_secret(&self) -> &str {
        &self.client_secret
    }

    /// An immutable reference to the authentication backend's URL.
    pub fn token_url(&self) -> &str {
        &self.token_url
    }
}
