use askama::Template;
use askama_axum::IntoResponse;
use axum::{
    extract::State, http::StatusCode, response::Html, routing::{get, post}, Json, Router
};
use base64::engine::{general_purpose::URL_SAFE, Engine};
use ring::{rand::{self, SecureRandom}, signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

// Store challenge and credential data
#[derive(Default)]
struct AuthStore {
    challenges: HashMap<String, Vec<u8>>,
    credentials: HashMap<String, StoredCredential>,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredCredential {
    credential_id: Vec<u8>,
    public_key: Vec<u8>,
    counter: u32,
}

#[derive(Clone)]
struct AppState {
    store: Arc<Mutex<AuthStore>>,
    rng: Arc<rand::SystemRandom>,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate;

#[derive(Deserialize)]
struct RegisterCredential {
    id: String,
    raw_id: String,
    response: AuthenticatorAttestationResponse,
    #[serde(rename = "type")]
    type_: String,
}

#[derive(Deserialize)]
struct AuthenticatorAttestationResponse {
    client_data_json: String,
    attestation_object: String,
}

#[derive(Serialize)]
struct AuthenticationOptions {
    challenge: String,
    timeout: u32,
    rp_id: String,
    allow_credentials: Vec<AllowCredential>,
    user_verification: String,
}

#[derive(Serialize)]
struct AllowCredential {
    r#type: String,
    id: String,
}

#[derive(Deserialize)]
struct AuthenticateCredential {
    id: String,
    raw_id: String,
    response: AuthenticatorAssertionResponse,
    #[serde(rename = "type")]
    type_: String,
}

#[derive(Deserialize)]
struct AuthenticatorAssertionResponse {
    authenticator_data: String,
    client_data_json: String,
    signature: String,
}

async fn index() -> impl IntoResponse {
    let template = IndexTemplate {};
    // Html(template.render().unwrap())
    (StatusCode::OK, Html(template.render().unwrap())).into_response()
}


#[derive(Serialize)]
struct UserInfo {
    id: String,
    name: String,
    display_name: String,
}


#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationOptions {
    challenge: String,
    rp_id: String,
    rp: RelyingParty,
    user: PublicKeyCredentialUserEntity,
    pub_key_cred_params: Vec<PubKeyCredParam>,
    authenticator_selection: AuthenticatorSelection,
    timeout: u32,
    attestation: String,
}

#[derive(Serialize)]
struct RelyingParty {
    name: String,
    id: String,
}

#[derive(Serialize)]
struct PublicKeyCredentialUserEntity {
    id: String,
    name: String,
    #[serde(rename = "displayName")]
    display_name: String,
}

#[derive(Serialize)]
struct PubKeyCredParam {
    #[serde(rename = "type")]
    type_: String,
    alg: i32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticatorSelection {
    authenticator_attachment: Option<String>,
    resident_key: String,
    user_verification: String,
}

async fn start_registration(
    State(state): State<AppState>,
    Json(username): Json<String>,
) -> Json<RegistrationOptions> {
    // Generate challenge
    let mut challenge = vec![0u8; 32];
    state.rng.fill(&mut challenge).unwrap();

    let mut store = state.store.lock().await;
    store.challenges.insert(username.clone(), challenge.clone());

    Json(RegistrationOptions {
        challenge: URL_SAFE.encode(&challenge),
        rp_id: "localhost".to_string(),
        rp: RelyingParty {
            name: "Passkey Demo".to_string(),
            id: "localhost".to_string(),
        },
        user: PublicKeyCredentialUserEntity {
            id: Uuid::new_v4().to_string(),
            name: username.clone(),
            display_name: username,
        },
        pub_key_cred_params: vec![PubKeyCredParam {
            type_: "public-key".to_string(),
            alg: -7, // ES256
        }],
        authenticator_selection: AuthenticatorSelection {
            authenticator_attachment: None,
            resident_key: "preferred".to_string(),
            user_verification: "preferred".to_string(),
        },
        timeout: 60000,
        attestation: "none".to_string(),
    })
}

async fn finish_registration(
    State(state): State<AppState>,
    Json(reg_data): Json<RegisterCredential>,
) -> &'static str {
    let mut store = state.store.lock().await;

    // Verify challenge
    let client_data: serde_json::Value = serde_json::from_str(&reg_data.response.client_data_json)
        .expect("Invalid client data JSON");

    let challenge = client_data["challenge"].as_str().unwrap();
    let decoded_challenge = URL_SAFE.decode(challenge).unwrap();

    // In production, verify the challenge matches stored challenge
    // and verify the origin matches expected origin

    // Parse attestation object (CBOR)
    let attestation_object = URL_SAFE
        .decode(&reg_data.response.attestation_object)
        .unwrap();
    // In production, parse CBOR to extract authData and verify format

    // For this example, we'll assume the public key is valid ES256
    // In production, validate the key format and signature
    let credential = StoredCredential {
        credential_id: URL_SAFE.decode(&reg_data.raw_id).unwrap(),
        public_key: vec![], // Extract from attestation_object
        counter: 0,
    };

    store.credentials.insert(reg_data.id, credential);
    "Registration successful"
}

async fn start_authentication(State(state): State<AppState>) -> Json<AuthenticationOptions> {
    let mut challenge = vec![0u8; 32];
    state.rng.fill(&mut challenge).unwrap();

    let store = state.store.lock().await;
    let allow_credentials: Vec<_> = store
        .credentials
        .iter()
        .map(|(id, _)| AllowCredential {
            r#type: "public-key".to_string(),
            id: id.clone(),
        })
        .collect();

    Json(AuthenticationOptions {
        challenge: URL_SAFE.encode(&challenge),
        timeout: 60000,
        rp_id: "localhost".to_string(),
        allow_credentials,
        user_verification: "preferred".to_string(),
    })
}

async fn verify_authentication(
    State(state): State<AppState>,
    Json(auth_data): Json<AuthenticateCredential>,
) -> &'static str {
    let store = state.store.lock().await;

    let credential = store
        .credentials
        .get(&auth_data.id)
        .expect("Unknown credential");

    // Verify the signature
    let client_data: serde_json::Value = serde_json::from_str(&auth_data.response.client_data_json)
        .expect("Invalid client data JSON");

    // In production:
    // 1. Verify challenge matches stored challenge
    // 2. Verify origin
    // 3. Verify rpId
    // 4. Verify type is "webauthn.get"
    // 5. Verify authenticator data format
    // 6. Verify signature using stored public key
    // 7. Verify counter increased

    "Authentication successful"
}

#[tokio::main]
async fn main() {
    let state = AppState {
        store: Arc::new(Mutex::new(AuthStore::default())),
        rng: Arc::new(rand::SystemRandom::new()),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/register/start", post(start_registration))
        .route("/register/finish", post(finish_registration))
        .route("/auth/start", post(start_authentication))
        .route("/auth/verify", post(verify_authentication))
        .with_state(state);

    println!("Starting server on http://localhost:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
