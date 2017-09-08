//! HTTP client.

use json;
use reqwest::{Client, IntoUrl, Method, RequestBuilder, StatusCode};
use reqwest::header::{Authorization, Bearer, ContentType, Headers};

use config::Config;
use error::{Result, ErrorKind, ResultExt};


/// An HTTP client.
pub struct Http<'c> {
    client: Client,
    config: &'c Config,
}

impl<'c> Http<'c> {
    /// Create a new client that points at the backend defined in the config.
    pub fn new(config: &'c Config) -> Result<Self> {
        let client = Client::new()?;
        Ok(Http { client, config })
    }

    /// HTTP GET.
    pub fn get<U: IntoUrl>(&self, url: U) -> Result<RequestBuilder> {
        self.request(Method::Get, url)
    }

    /// HTTP POST.
    pub fn post<U: IntoUrl>(&self, url: U) -> Result<RequestBuilder> {
        self.request(Method::Post, url)
    }

    /// HTTP PUT.
    pub fn put<U: IntoUrl>(&self, url: U) -> Result<RequestBuilder> {
        self.request(Method::Put, url)
    }

    /// HTTP DELETE.
    pub fn delete<U: IntoUrl>(&self, url: U) -> Result<RequestBuilder> {
        self.request(Method::Delete, url)
    }

    fn request<U: IntoUrl>(&self, method: Method, url: U) -> Result<RequestBuilder> {
        let token = self.generate_token()?;
        let mut req = self.client.request(method, url)?;
        let mut headers = Headers::new();
        headers.set(Authorization(Bearer { token: token.access_token }));
        let _ = req.headers(headers);
        Ok(req)
    }

    // TODO should consider caching token
    fn generate_token(&self) -> Result<AccessToken> {
        let mut headers = Headers::new();
        headers.set(ContentType::form_url_encoded());

        let url = format!("{}/token", self.config.auth().token_url());
        let client_id = format!("{}", self.config.auth().client_id());
        let resp = self.client
            .post(&url)
            .chain_err(|| format!("Bad URL: {}", url))?
            .basic_auth(client_id, Some(self.config.auth().client_secret()))
            .headers(headers)
            .body("grant_type=client_credentials")
            .send()
            .chain_err(|| format!("Faile to POST to URL: {}", url))?;

        if resp.status() != StatusCode::Ok {
            bail!(ErrorKind::Runtime(format!(
                    "Bad status code {:?} for POST {}",
                    resp.status(),
                    url,
                )));
        } else {
            json::from_reader(resp).chain_err(|| "Failed to parse access token")
        }
    }
}

/// An access token for the OTA+ API.
#[derive(Serialize, Deserialize, Debug)]
struct AccessToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i32,
    pub scope: String,
}
