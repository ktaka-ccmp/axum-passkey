use base64::engine::{general_purpose::URL_SAFE, Engine};
use dotenv::dotenv;
use ring::rand;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
struct AppConfig {
    origin: String,
    rp_id: String,
}

#[derive(Default)]
struct AuthStore {
    challenges: HashMap<String, StoredChallenge>,
    credentials: HashMap<String, StoredCredential>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct StoredChallenge {
    challenge: Vec<u8>,
    username: String,
    timestamp: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct StoredCredential {
    credential_id: Vec<u8>,
    public_key: Vec<u8>,
    counter: u32,
}

fn base64url_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let padding_len = (4 - input.len() % 4) % 4;
    let padded = format!("{}{}", input, "=".repeat(padding_len));
    URL_SAFE.decode(padded)
}

// Public things
pub(crate) mod auth;
pub(crate) mod register;

#[derive(Clone)]
pub(crate) struct AppState {
    store: Arc<Mutex<AuthStore>>,
    rng: Arc<rand::SystemRandom>,
    config: AppConfig,
}

pub(crate) fn app_state() -> AppState {
    dotenv().ok();

    let origin = env::var("ORIGIN").expect("ORIGIN must be set");
    let rp_id = origin
        .strip_prefix("https://")
        .unwrap_or(&origin)
        .split(':')
        .next()
        .unwrap()
        .to_string();

    let config = AppConfig { origin, rp_id };
    AppState {
        store: Arc::new(Mutex::new(AuthStore::default())),
        rng: Arc::new(rand::SystemRandom::new()),
        config,
    }
}
