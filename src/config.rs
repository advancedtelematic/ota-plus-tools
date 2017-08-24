use interchange::InterchangeType;
use uuid::Uuid;


#[derive(Serialize, Deserialize)]
pub struct Config {
    app: AppConfig,
    auth: AuthConfig,
}

impl Config {
    pub fn new(app: AppConfig, auth: AuthConfig) -> Self {
        Config { app, auth }
    }

    pub fn auth(&self) -> &AuthConfig {
        &self.auth
    }

    pub fn app(&self) -> &AppConfig {
        &self.app
    }
}

#[derive(Serialize, Deserialize)]
pub struct AppConfig {
    interchange: InterchangeType,
    tuf_url: String
}

impl AppConfig {
    pub fn new(interchange: InterchangeType, tuf_url: String) -> Self {
        AppConfig { interchange, tuf_url }
    }

    pub fn interchange(&self) -> InterchangeType {
        self.interchange
    }

    pub fn tuf_url(&self) -> &str {
        &self.tuf_url
    }
}

#[derive(Serialize, Deserialize)]
pub struct AuthConfig {
    client_id: Uuid,
    client_secret: String,
    repo_id: String,
    token_url: String,
}

impl AuthConfig {
    pub fn new(client_id: Uuid, client_secret: String, repo_id: String, token_url: String) -> Self {
        AuthConfig { client_id, client_secret, repo_id, token_url }
    }

    pub fn client_id(&self) -> Uuid {
        self.client_id
    }

    pub fn client_secret(&self) -> &str {
        &self.client_secret
    }

    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    pub fn token_url(&self) -> &str {
        &self.token_url
    }
}
