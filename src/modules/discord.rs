use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::blocking::Client;
use serde_derive::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
pub struct Profile {
    pub id: String,
    pub username: String,
    pub avatar: Option<String>,
    pub discriminator: String,
    pub public_flags: i32,
    pub premium_type: i32,
    pub flags: i32,
    pub global_name: String,
    pub mfa_enabled: bool,
    pub locale: String,
    pub email: Option<String>,
    pub verified: bool,
    pub phone: Option<String>,
    pub nsfw_allowed: bool,
    pub bio: String,
}

pub struct Discord {
    headers: HeaderMap,
    client: Client,
}

impl Discord {
    pub fn new(token: &str) -> Discord {
        let mut headers = get_headers("125");
        headers.insert("authorization", HeaderValue::from_str(token).unwrap());

        let client = Client::new();

        Discord {
            headers: headers,
            client: client,
        }
    }

    pub fn get_profile(&self) -> Result<Profile, Box<dyn std::error::Error>> {
        let resp = self.client
            .get("https://discord.com/api/v9/users/@me")
            .headers(self.headers.clone())
            .send()?;

        if !resp.status().is_success() {
            return Err(From::from("Failed to retrieve profile"));
        }

        let profile: Profile = resp.json()?;
        Ok(profile)
    }
}


fn get_headers(chrome_v: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("accept", HeaderValue::from_static("*/*"));
    headers.insert("accept-language", HeaderValue::from_static("en-US;q=0.8,en;q=0.7"));
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert("connection", HeaderValue::from_static("keep-alive"));
    headers.insert("sec-ch-ua", HeaderValue::from_str(&format!("\"Chromium\";v=\"{}\", \"Google Chrome\";v=\"{}\", \"Not;A=Brand\";v=\"24\"", chrome_v, chrome_v)).unwrap());
    headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
    headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"Windows\""));
    headers.insert("sec-fetch-dest", HeaderValue::from_static("empty"));
    headers.insert("sec-fetch-mode", HeaderValue::from_static("cors"));
    headers.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
    headers.insert("user-agent", HeaderValue::from_str(&format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36", chrome_v)).unwrap());
    headers
}