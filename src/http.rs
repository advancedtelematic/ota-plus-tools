use json;
use reqwest::{Client, IntoUrl, Method, RequestBuilder, StatusCode};
use reqwest::header::{Authorization, Bearer, ContentType, Headers};

use config::Config;
use error::{Result, ErrorKind};


pub struct Http<'c> {
    client: Client,
    config: &'c Config,
}

impl<'c> Http<'c> {
    pub fn new(config: &'c Config) -> Result<Self> {
        let client = Client::new()?;
        Ok(Http { client, config })
    }

    pub fn get<U: IntoUrl>(&self, url: U) -> Result<RequestBuilder> {
        self.request(Method::Get, url)
    }

    pub fn post<U: IntoUrl>(&self, url: U) -> Result<RequestBuilder> {
        self.request(Method::Post, url)
    }

    pub fn put<U: IntoUrl>(&self, url: U) -> Result<RequestBuilder> {
        self.request(Method::Put, url)
    }

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

    fn generate_token(&self) -> Result<AccessToken> {
        let mut headers = Headers::new();
        headers.set(ContentType::form_url_encoded());

        let client_id = format!("{}", self.config.auth().client_id());
        let resp = self.client
            .post(&format!("{}/token", self.config.auth().token_url()))?
            .basic_auth(client_id, Some(self.config.auth().client_secret()))
            .headers(headers)
            .body("grant_type=client_credentials")
            .send()?;

        if resp.status() != StatusCode::Ok {
            bail!(ErrorKind::Runtime(
                format!("Bad status code: {:?}", resp.status()),
            ));
        } else {
            json::from_reader(resp).map_err(|e| e.into())
        }
    }
}


#[derive(Serialize, Deserialize, Debug)]
struct AccessToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i32,
    pub scope: String,
}
