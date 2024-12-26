use askama::Template;
use askama_axum::IntoResponse;
use axum::{
    extract::State,
    http::StatusCode,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use base64::engine::{general_purpose::URL_SAFE, Engine};
use ring::{
    rand::{self, SecureRandom},
    signature,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

use dotenv::dotenv;
use std::env;

// Store challenge and credential data
#[derive(Default)]
struct AuthStore {
    challenges: HashMap<String, Vec<u8>>,
    credentials: HashMap<String, StoredCredential>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct StoredCredential {
    credential_id: Vec<u8>,
    public_key: Vec<u8>,
    counter: u32,
}

#[derive(Clone)]
struct AppConfig {
    origin: String,
    rp_id: String,
}

// Update AppState to include config
#[derive(Clone)]
struct AppState {
    store: Arc<Mutex<AuthStore>>,
    rng: Arc<rand::SystemRandom>,
    config: AppConfig,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate;

#[derive(Deserialize, Debug)]
struct RegisterCredential {
    id: String,
    raw_id: String,
    response: AuthenticatorAttestationResponse,
    #[serde(rename = "type")]
    type_: String,
}

#[derive(Deserialize, Debug)]
struct AuthenticatorAttestationResponse {
    client_data_json: String,
    attestation_object: String,
}

#[derive(Deserialize, Debug)]
struct AuthenticateCredential {
    id: String,
    raw_id: String,
    response: AuthenticatorAssertionResponse,
    #[serde(rename = "type")]
    type_: String,
}

#[derive(Deserialize, Debug)]
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
    println!("Registering user: {}", username);
    // Generate challenge
    let mut challenge = vec![0u8; 32];
    state.rng.fill(&mut challenge).unwrap();

    let mut store = state.store.lock().await;
    store.challenges.insert(username.clone(), challenge.clone());

    Json(RegistrationOptions {
        challenge: URL_SAFE.encode(&challenge),
        rp_id: state.config.rp_id.clone(),
        rp: RelyingParty {
            name: "Passkey Demo".to_string(),
            id: state.config.rp_id.clone(),
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

// Add this helper function at the module level
fn base64url_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // Add padding if necessary
    let padding_len = (4 - input.len() % 4) % 4;
    let padded = format!("{}{}", input, "=".repeat(padding_len));
    URL_SAFE.decode(padded)
}

use ciborium::value::{Integer, Value as CborValue};

async fn finish_registration(
    State(state): State<AppState>,
    Json(reg_data): Json<RegisterCredential>,
) -> Result<&'static str, (StatusCode, String)> {
    println!("Registering user: {:?}", reg_data);

    let mut store = state.store.lock().await;

    // Decode and parse client data
    let decoded_client_data =
        base64url_decode(&reg_data.response.client_data_json).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Failed to decode client data: {}", e),
            )
        })?;

    let client_data_str = String::from_utf8(decoded_client_data).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Client data is not valid UTF-8: {}", e),
        )
    })?;

    let client_data: serde_json::Value = serde_json::from_str(&client_data_str).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid client data JSON: {}", e),
        )
    })?;

    println!("Decoded client data: {}", client_data);

    // Verify the origin matches what we expect
    let origin = client_data["origin"].as_str().ok_or((
        StatusCode::BAD_REQUEST,
        "Missing origin in client data".to_string(),
    ))?;

    if origin != state.config.origin {
        return Err((StatusCode::BAD_REQUEST, "Invalid origin".to_string()));
    }

    // Verify the type is webauthn.create
    let type_ = client_data["type"].as_str().ok_or((
        StatusCode::BAD_REQUEST,
        "Missing type in client data".to_string(),
    ))?;

    if type_ != "webauthn.create" {
        return Err((StatusCode::BAD_REQUEST, "Invalid type".to_string()));
    }

    // Get and verify challenge
    let challenge = client_data["challenge"].as_str().ok_or((
        StatusCode::BAD_REQUEST,
        "Missing challenge in client data".to_string(),
    ))?;

    let decoded_challenge = base64url_decode(challenge).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to decode challenge: {}", e),
        )
    })?;

    // Decode attestation object
    let attestation_object =
        base64url_decode(&reg_data.response.attestation_object).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Failed to decode attestation object: {}", e),
            )
        })?;

    // Parse the attestation object as CBOR
    let attestation_cbor: CborValue = ciborium::de::from_reader(&attestation_object[..])
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid CBOR data: {}", e)))?;

    // Extract the authData from the attestation
    let auth_data = if let CborValue::Map(map) = attestation_cbor {
        let mut auth_data = None;

        for (key, value) in map {
            if let CborValue::Text(key_str) = key {
                if key_str == "authData" {
                    if let CborValue::Bytes(data) = value {
                        auth_data = Some(data);
                        break;
                    }
                }
            }
        }

        auth_data.ok_or((
            StatusCode::BAD_REQUEST,
            "Missing or invalid authData".to_string(),
        ))?
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid attestation format".to_string(),
        ));
    };

    // After getting auth_data, let's debug print more details
    println!("Auth data length: {}", auth_data.len());
    println!("Auth data (hex): {:02x?}", auth_data);

    // The public key is in COSE format in the credential data portion of authData
    // First 37 bytes:
    // - RP ID hash (32 bytes)
    // - flags (1 byte)
    // - counter (4 bytes)
    let mut pos = 37;

    // Check if attested credential data present
    let flags = auth_data[32];
    let has_attested_cred_data = (flags & 0x40) != 0;

    if !has_attested_cred_data {
        return Err((
            StatusCode::BAD_REQUEST,
            "No attested credential data present".to_string(),
        ));
    }

    println!("Flags: {:08b}", flags);

    if auth_data.len() < pos + 18 {
        // 16-byte AAGUID + 2-byte credential ID length
        return Err((
            StatusCode::BAD_REQUEST,
            "Authenticator data too short".to_string(),
        ));
    }

    // Skip AAGUID
    pos += 16;

    // Get credential ID length (16-bit big-endian)
    let cred_id_len = ((auth_data[pos] as usize) << 8) | (auth_data[pos + 1] as usize);
    println!(
        "Reading cred_id_len at pos {} and {}: {:02x} {:02x}",
        pos,
        pos + 1,
        auth_data[pos],
        auth_data[pos + 1]
    );
    println!("Credential ID length: {}", cred_id_len);

    pos += 2;

    if cred_id_len == 0 || cred_id_len > 1024 {
        // Sanity check
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid credential ID length".to_string(),
        ));
    }

    println!("Credential ID length: {}", cred_id_len);
    println!("Current position: {}", pos);
    println!("Remaining data length: {}", auth_data.len() - pos);

    if auth_data.len() < pos + cred_id_len {
        return Err((
            StatusCode::BAD_REQUEST,
            "Authenticator data too short for credential ID".to_string(),
        ));
    }

    // Skip credential ID
    pos += cred_id_len;

    println!("Position after credential ID: {}", pos);
    println!("Remaining data length: {}", auth_data.len() - pos);

    // The remaining data is the CBOR-encoded public key
    let public_key_cbor: CborValue = ciborium::de::from_reader(&auth_data[pos..]).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid public key CBOR: {}", e),
        )
    })?;

    // Extract the x and y coordinates from the COSE key
    let (x_coord, y_coord) = if let CborValue::Map(map) = public_key_cbor {
        let mut x_coord = None;
        let mut y_coord = None;

        for (key, value) in map {
            if let CborValue::Integer(i) = key {
                if i == Integer::from(-2) {
                    if let CborValue::Bytes(x) = value {
                        x_coord = Some(x);
                    }
                } else if i == Integer::from(-3) {
                    if let CborValue::Bytes(y) = value {
                        y_coord = Some(y);
                    }
                }
            }
        }

        match (x_coord, y_coord) {
            (Some(x), Some(y)) => (x, y),
            _ => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Missing or invalid key coordinates".to_string(),
                ))
            }
        }
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid public key format".to_string(),
        ));
    };

    // Construct the uncompressed EC public key format (0x04 || x || y)
    let mut public_key = Vec::with_capacity(65);
    public_key.push(0x04); // Uncompressed point format
    public_key.extend_from_slice(&x_coord);
    public_key.extend_from_slice(&y_coord);

    println!("Extracted public key: {:?}", public_key);

    // Decode credential ID
    let credential_id = base64url_decode(&reg_data.raw_id).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to decode credential ID: {}", e),
        )
    })?;

    // Store the credential
    let credential = StoredCredential {
        credential_id,
        public_key,
        counter: 0,
    };

    store.credentials.insert(reg_data.id, credential);
    Ok("Registration successful")
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AuthenticationOptions {
    challenge: String,
    timeout: u32,
    rp_id: String,
    allow_credentials: Vec<AllowCredential>,
    user_verification: String,
}

#[derive(Serialize, Debug)]
struct AllowCredential {
    #[serde(rename = "type")]
    type_: String,
    id: String,
}

async fn start_authentication(State(state): State<AppState>) -> Json<AuthenticationOptions> {
    let mut challenge = vec![0u8; 32];
    state.rng.fill(&mut challenge).unwrap();

    let store = state.store.lock().await;
    let allow_credentials: Vec<_> = store
        .credentials
        .iter()
        .map(|(id, _)| AllowCredential {
            type_: "public-key".to_string(),
            id: id.clone(),
        })
        .collect();

    let options = AuthenticationOptions {
        challenge: URL_SAFE.encode(&challenge),
        timeout: 60000,
        rp_id: state.config.rp_id.clone(),
        allow_credentials,
        user_verification: "preferred".to_string(),
    };

    println!("Starting authentication: {:?}", options);

    Json(options)
}

use ring::{digest, signature::UnparsedPublicKey, signature::VerificationAlgorithm};

async fn verify_authentication(
    State(state): State<AppState>,
    Json(auth_data): Json<AuthenticateCredential>,
) -> Result<&'static str, (StatusCode, String)> {
    let store = state.store.lock().await;

    println!("Authenticating user: {:?}", auth_data);

    // Decode client data JSON
    let decoded_client_data =
        base64url_decode(&auth_data.response.client_data_json).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Failed to decode client data: {}", e),
            )
        })?;

    let client_data_str = String::from_utf8(decoded_client_data.clone()).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Client data is not valid UTF-8: {}", e),
        )
    })?;

    let client_data: serde_json::Value = serde_json::from_str(&client_data_str).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid client data JSON: {}", e),
        )
    })?;

    println!("Decoded client data: {}", client_data);

    // Verify origin
    let origin = client_data["origin"].as_str().ok_or((
        StatusCode::BAD_REQUEST,
        "Missing origin in client data".to_string(),
    ))?;

    if origin != state.config.origin {
        return Err((StatusCode::BAD_REQUEST, "Invalid origin".to_string()));
    }

    // Verify type
    let type_ = client_data["type"].as_str().ok_or((
        StatusCode::BAD_REQUEST,
        "Missing type in client data".to_string(),
    ))?;

    if type_ != "webauthn.get" {
        return Err((StatusCode::BAD_REQUEST, "Invalid type".to_string()));
    }

    // Decode authenticator data
    let auth_data_bytes =
        base64url_decode(&auth_data.response.authenticator_data).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Failed to decode authenticator data: {}", e),
            )
        })?;

    // Verify RP ID hash (first 32 bytes of authenticator data)
    let rp_id_hash = digest::digest(&digest::SHA256, state.config.rp_id.as_bytes());
    if auth_data_bytes[..32] != rp_id_hash.as_ref()[..] {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid RP ID hash in authenticator data".to_string(),
        ));
    }

    // Check user presence flag (bit 0 of flags byte)
    let flags = auth_data_bytes[32];
    if flags & 0x01 != 0x01 {
        return Err((
            StatusCode::BAD_REQUEST,
            "User presence flag not set".to_string(),
        ));
    }

    // Compute client data hash
    let client_data_hash = digest::digest(&digest::SHA256, &decoded_client_data);

    // Verify signature
    // The signature is over the concatenation of authenticator data and client data hash
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&auth_data_bytes);
    signed_data.extend_from_slice(client_data_hash.as_ref());

    // Decode signature
    let signature = base64url_decode(&auth_data.response.signature).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to decode signature: {}", e),
        )
    })?;

    // Verify using stored public key (assuming ES256)

    // Get stored credential
    let credential = store
        .credentials
        .get(&auth_data.id)
        .ok_or((StatusCode::BAD_REQUEST, "Unknown credential".to_string()))?;

    let verification_algorithm = &ring::signature::ECDSA_P256_SHA256_ASN1;
    let public_key = UnparsedPublicKey::new(verification_algorithm, &credential.public_key);

    public_key
        .verify(&signed_data, &signature)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature".to_string()))?;

    Ok("Authentication successful")
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    // Get configuration from environment variables
    let origin = env::var("ORIGIN").expect("ORIGIN must be set");
    let rp_id = origin
        .strip_prefix("https://")
        .unwrap_or(&origin)
        .split(':')
        .next()
        .unwrap()
        .to_string();

    let config = AppConfig { origin, rp_id };

    let state = AppState {
        store: Arc::new(Mutex::new(AuthStore::default())),
        rng: Arc::new(rand::SystemRandom::new()),
        config,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/register/start", post(start_registration))
        .route(
            "/register/finish",
            post(|state, json| async move {
                match finish_registration(state, json).await {
                    Ok(message) => (StatusCode::OK, message.to_string()),
                    Err((status, message)) => (status, message),
                }
            }),
        )
        .route("/auth/start", post(start_authentication))
        .route(
            "/auth/verify",
            post(|state, json| async move {
                match verify_authentication(state, json).await {
                    Ok(message) => (StatusCode::OK, message.to_string()),
                    Err((status, message)) => (status, message),
                }
            }),
        )
        .with_state(state);

    println!("Starting server on http://localhost:3001");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
