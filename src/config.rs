use interchange::InterchangeType;

#[derive(Serialize, Deserialize)]
pub struct Config {
    app: AppConfig,
    auth: AuthConfig,
}

impl Config {
    pub fn new(app: AppConfig, auth: AuthConfig) -> Self {
        Config {
            app: app,
            auth: auth,
        }
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
    uri: String,
}

impl AppConfig {
    pub fn new(interchange: InterchangeType, uri: String) -> Self {
        AppConfig {
            interchange: interchange,
            uri: uri,
        }
    }

    pub fn interchange(&self) -> &InterchangeType {
        &self.interchange
    }

    pub fn uri(&self) -> &str {
        &self.uri
    }
}

#[derive(Serialize, Deserialize)]
pub struct AuthConfig {
    client_id: String,
    client_secret: String,
    repo_id: String,
}

impl AuthConfig {
    pub fn new(client_id: String, client_secret: String, repo_id: String) -> Self {
        AuthConfig {
            client_id: client_id,
            client_secret: client_secret,
            repo_id: repo_id,
        }
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn client_secret(&self) -> &str {
        &self.client_secret
    }

    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }
}
