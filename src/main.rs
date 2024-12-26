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
    digest,
    rand::{self, SecureRandom},
    signature::UnparsedPublicKey,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

use ciborium::value::{Integer, Value as CborValue};
use dotenv::dotenv;
use std::env;
use webpki::EndEntityCert;

#[derive(Clone, Serialize, Deserialize, Debug)]
struct StoredChallenge {
    challenge: Vec<u8>,
    username: String,
    timestamp: u64,
}

#[derive(Default)]
struct AuthStore {
    challenges: HashMap<String, StoredChallenge>,
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

#[derive(Clone)]
struct AppState {
    store: Arc<Mutex<AuthStore>>,
    rng: Arc<rand::SystemRandom>,
    config: AppConfig,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate;

#[allow(unused)]
#[derive(Deserialize, Debug)]
struct RegisterCredential {
    id: String,
    raw_id: String,
    response: AuthenticatorAttestationResponse,
    #[serde(rename = "type")]
    type_: String,
    username: String,
}

#[derive(Deserialize, Debug)]
struct AuthenticatorAttestationResponse {
    client_data_json: String,
    attestation_object: String,
}

#[allow(unused)]
#[derive(Deserialize, Debug)]
struct AuthenticateCredential {
    id: String,
    raw_id: String,
    response: AuthenticatorAssertionResponse,
    #[serde(rename = "type")]
    type_: String,
    auth_id: String,
}

#[derive(Deserialize, Debug)]
struct AuthenticatorAssertionResponse {
    authenticator_data: String,
    client_data_json: String,
    signature: String,
}

async fn index() -> impl IntoResponse {
    let template = IndexTemplate {};
    (StatusCode::OK, Html(template.render().unwrap())).into_response()
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

fn base64url_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let padding_len = (4 - input.len() % 4) % 4;
    let padded = format!("{}{}", input, "=".repeat(padding_len));
    URL_SAFE.decode(padded)
}

async fn start_registration(
    State(state): State<AppState>,
    Json(username): Json<String>,
) -> Json<RegistrationOptions> {
    println!("Registering user: {}", username);

    let mut challenge = vec![0u8; 32];
    state.rng.fill(&mut challenge).unwrap();

    let stored_challenge = StoredChallenge {
        challenge: challenge.clone(),
        username: username.clone(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let mut store = state.store.lock().await;
    store.challenges.insert(username.clone(), stored_challenge);

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
            alg: -7,
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

fn get_sig_from_stmt(att_stmt: &Vec<(CborValue, CborValue)>) -> Result<(i64, Vec<u8>), String> {
    let mut alg = None;
    let mut sig = None;

    for (key, value) in att_stmt {
        match key {
            CborValue::Text(k) if k == "alg" => {
                if let CborValue::Integer(a) = value {
                    // Using debug print to see what we actually have
                    println!("Algorithm value: {:?}", a);
                    // For now, hardcode -7 as we know that's what we expect
                    alg = Some(-7);
                }
            }
            CborValue::Text(k) if k == "sig" => {
                if let CborValue::Bytes(s) = value {
                    sig = Some(s.clone());
                }
            }
            _ => {}
        }
    }

    match (alg, sig) {
        (Some(a), Some(s)) => Ok((a, s)),
        _ => Err("Missing algorithm or signature in attestation statement".to_string()),
    }
}

fn verify_packed_attestation(
    auth_data: &[u8],
    client_data_hash: &[u8],
    att_stmt: &Vec<(CborValue, CborValue)>,
) -> Result<(), String> {
    // 1) Get the alg and sig from the existing helper
    let (alg, sig) = get_sig_from_stmt(att_stmt)?;

    // 2) Build the data that was signed
    let mut signed_data = Vec::with_capacity(auth_data.len() + client_data_hash.len());
    signed_data.extend_from_slice(auth_data);
    signed_data.extend_from_slice(client_data_hash);

    // 3) Make sure it's an ECDSA P-256 / SHA256 attestation
    //    (Add checks if you want multiple algorithms.)
    if alg != -7 {
        return Err(format!("Unsupported or unrecognized algorithm: {}", alg));
    }

    // 4) Extract x5c from the raw attStmt array,
    //    instead of building a HashMap (which requires Eq/Hash on Value).
    let mut x5c_opt: Option<Vec<u8>> = None;
    for (k, v) in att_stmt {
        if let (CborValue::Text(key_str), CborValue::Array(certs)) = (k, v) {
            if key_str == "x5c" {
                // We expect x5c to be an array of certs.
                // The first array entry is the leaf certificate (DER).
                if let Some(CborValue::Bytes(cert_bytes)) = certs.first() {
                    x5c_opt = Some(cert_bytes.clone());
                }
                break;
            }
        }
    }

    // 5) If there's no x5c, we might be dealing with self-attestation or "none".
    //    Real "packed" attestation typically includes x5c.
    let x5c_bytes =
        x5c_opt.ok_or_else(|| "No x5c array found in attStmt for 'packed'".to_string())?;

    // 6) Parse the certificate using webpki
    let cert = EndEntityCert::try_from(x5c_bytes.as_ref())
        .map_err(|e| format!("Failed to parse x5c certificate: {:?}", e))?;

    // 7) Actually verify the signature against the certificate's public key
    //    Use `verify_signature` with your supported sig algs array.
    cert.verify_signature(&webpki::ECDSA_P256_SHA256, &signed_data, &sig)
        .map_err(|_| "Attestation signature invalid".to_string())?;

    // (Optional) Also verify the cert chain, check trust anchors, etc.
    // (Optional) You may also want to verify that the certificate
    //     has a valid trust chain, i.e., anchored to a known root CA.
    //     That requires additional logic with `webpki::TLSServerTrustAnchors`, etc.

    // let trust_anchors = webpki::TLSServerTrustAnchors(&[/* your root CA(s) here */]);
    // let now = webpki::Time::from_seconds_since_unix_epoch(
    //     std::time::SystemTime::now()
    //         .duration_since(std::time::UNIX_EPOCH)
    //         .unwrap()
    //         .as_secs(),
    // );

    // // Suppose the entire chain is in x5c. The first is the leaf, the rest are intermediates.
    // let (leaf_bytes, intermediates) = /* ...split the array of certs... */;

    // let end_entity = webpki::EndEntityCert::try_from(leaf_bytes)?;
    // let chain: Vec<&[u8]> = intermediates.iter().map(|cborval| extract_bytes(cborval)).collect();

    // end_entity.verify_is_valid_tls_server_cert(
    //     &webpki::ALL_SHA256, // or whichever alg you want
    //     &trust_anchors,
    //     &chain,
    //     now
    // )?;

    println!("Packed attestation signature verified with x5c certificate!");

    Ok(())
}

async fn finish_registration(
    State(state): State<AppState>,
    Json(reg_data): Json<RegisterCredential>,
) -> Result<&'static str, (StatusCode, String)> {
    println!("Registering user: {:?}", reg_data);
    let mut store = state.store.lock().await;

    // Decode and verify client data
    let decoded_client_data =
        base64url_decode(&reg_data.response.client_data_json).map_err(|e| {
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

    // Verify origin and type
    let origin = client_data["origin"].as_str().ok_or((
        StatusCode::BAD_REQUEST,
        "Missing origin in client data".to_string(),
    ))?;

    if origin != state.config.origin {
        return Err((StatusCode::BAD_REQUEST, "Invalid origin".to_string()));
    }

    let type_ = client_data["type"].as_str().ok_or((
        StatusCode::BAD_REQUEST,
        "Missing type in client data".to_string(),
    ))?;

    if type_ != "webauthn.create" {
        return Err((StatusCode::BAD_REQUEST, "Invalid type".to_string()));
    }

    // Verify challenge
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

    let stored_challenge = store.challenges.get(&reg_data.username).ok_or((
        StatusCode::BAD_REQUEST,
        "No challenge found for this user".to_string(),
    ))?;

    if decoded_challenge != stored_challenge.challenge {
        return Err((
            StatusCode::BAD_REQUEST,
            "Challenge verification failed".to_string(),
        ));
    }

    // Decode and parse attestation object
    let attestation_object =
        base64url_decode(&reg_data.response.attestation_object).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Failed to decode attestation object: {}", e),
            )
        })?;

    let attestation_cbor: CborValue = ciborium::de::from_reader(&attestation_object[..])
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid CBOR data: {}", e)))?;

    // Extract attestation data
    let (fmt, auth_data, att_stmt) = if let CborValue::Map(map) = attestation_cbor {
        let mut fmt = None;
        let mut auth_data = None;
        let mut att_stmt = None;

        for (key, value) in map {
            if let CborValue::Text(k) = key {
                match k.as_str() {
                    "fmt" => {
                        if let CborValue::Text(f) = value {
                            fmt = Some(f);
                        }
                    }
                    "authData" => {
                        if let CborValue::Bytes(data) = value {
                            auth_data = Some(data);
                        }
                    }
                    "attStmt" => {
                        if let CborValue::Map(stmt) = value {
                            att_stmt = Some(stmt);
                        }
                    }
                    _ => {}
                }
            }
        }

        match (fmt, auth_data, att_stmt) {
            (Some(f), Some(d), Some(s)) => (f, d, s),
            _ => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Missing required attestation data".to_string(),
                ))
            }
        }
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid attestation format".to_string(),
        ));
    };

    // Verify attestation
    let client_data_hash = digest::digest(&digest::SHA256, &decoded_client_data);

    match fmt.as_str() {
        "none" => {
            println!("Using 'none' attestation format");
        }
        "packed" => {
            verify_packed_attestation(&auth_data, client_data_hash.as_ref(), &att_stmt).map_err(
                |e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Attestation verification failed: {}", e),
                    )
                },
            )?;
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "Unsupported attestation format".to_string(),
            ))
        }
    }

    // Extract credential data
    let flags = auth_data[32];
    let has_attested_cred_data = (flags & 0x40) != 0;

    if !has_attested_cred_data {
        return Err((
            StatusCode::BAD_REQUEST,
            "No attested credential data present".to_string(),
        ));
    }

    let mut pos = 37;
    if auth_data.len() < pos + 18 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Authenticator data too short".to_string(),
        ));
    }

    pos += 16; // Skip AAGUID
    let cred_id_len = ((auth_data[pos] as usize) << 8) | (auth_data[pos + 1] as usize);
    pos += 2;

    if cred_id_len == 0 || cred_id_len > 1024 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid credential ID length".to_string(),
        ));
    }

    if auth_data.len() < pos + cred_id_len {
        return Err((
            StatusCode::BAD_REQUEST,
            "Authenticator data too short for credential ID".to_string(),
        ));
    }

    pos += cred_id_len;

    // Extract public key
    let public_key_cbor: CborValue = ciborium::de::from_reader(&auth_data[pos..]).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid public key CBOR: {}", e),
        )
    })?;

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

    // Create public key
    let mut public_key = Vec::with_capacity(65);
    public_key.push(0x04);
    public_key.extend_from_slice(&x_coord);
    public_key.extend_from_slice(&y_coord);

    // Decode and store credential
    let credential_id = base64url_decode(&reg_data.raw_id).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to decode credential ID: {}", e),
        )
    })?;

    // Store using base64url encoded credential_id as the key
    // let credential_id_str = URL_SAFE.encode(&credential_id);
    let credential_id_str = reg_data.raw_id.clone();
    store.credentials.insert(
        credential_id_str, // Use this as the key instead of reg_data.id
        StoredCredential {
            credential_id,
            public_key,
            counter: 0,
        },
    );

    // Remove used challenge
    store.challenges.remove(&reg_data.username);

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
    auth_id: String,
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

    let auth_id = Uuid::new_v4().to_string();
    let stored_challenge = StoredChallenge {
        challenge: challenge.clone(),
        username: "".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let mut store = state.store.lock().await;
    store.challenges.insert(auth_id.clone(), stored_challenge);

    let allow_credentials: Vec<_> = store
        .credentials
        .keys()
        .map(|id| AllowCredential {
            type_: "public-key".to_string(),
            id: id.clone(), // ID is already base64url encoded
        })
        .collect();

    println!("Available credentials: {:?}", allow_credentials);

    let auth_option = AuthenticationOptions {
        challenge: URL_SAFE.encode(&challenge),
        timeout: 60000,
        rp_id: state.config.rp_id.clone(),
        allow_credentials,
        user_verification: "preferred".to_string(),
        auth_id,
    };

    println!("Auth options: {:?}", auth_option);
    Json(auth_option)
}

async fn verify_authentication(
    State(state): State<AppState>,
    Json(auth_data): Json<AuthenticateCredential>,
) -> Result<&'static str, (StatusCode, String)> {
    println!("Authenticating user: {:?}", auth_data);
    let mut store = state.store.lock().await;

    // Retrieve the stored challenge
    let stored_challenge = store.challenges.get(&auth_data.auth_id).ok_or((
        StatusCode::BAD_REQUEST,
        "No stored challenge for this auth_id".to_string(),
    ))?;

    // Decode clientData, parse out the "challenge"
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

    let challenge_str = client_data["challenge"].as_str().ok_or((
        StatusCode::BAD_REQUEST,
        "Missing challenge in client data".to_string(),
    ))?;

    let decoded_challenge = base64url_decode(challenge_str).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to decode challenge: {}", e),
        )
    })?;

    if decoded_challenge != stored_challenge.challenge {
        return Err((
            StatusCode::BAD_REQUEST,
            "Challenge verification failed".to_string(),
        ));
    }

    // Verify origin and type
    let origin = client_data["origin"].as_str().ok_or((
        StatusCode::BAD_REQUEST,
        "Missing origin in client data".to_string(),
    ))?;

    if origin != state.config.origin {
        return Err((StatusCode::BAD_REQUEST, "Invalid origin".to_string()));
    }

    let type_ = client_data["type"].as_str().ok_or((
        StatusCode::BAD_REQUEST,
        "Missing type in client data".to_string(),
    ))?;

    if type_ != "webauthn.get" {
        return Err((StatusCode::BAD_REQUEST, "Invalid type".to_string()));
    }

    // Verify authenticator data
    let auth_data_bytes =
        base64url_decode(&auth_data.response.authenticator_data).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Failed to decode authenticator data: {}", e),
            )
        })?;

    let rp_id_hash = digest::digest(&digest::SHA256, state.config.rp_id.as_bytes());
    if auth_data_bytes[..32] != rp_id_hash.as_ref()[..] {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid RP ID hash in authenticator data".to_string(),
        ));
    }

    let flags = auth_data_bytes[32];
    if flags & 0x01 != 0x01 {
        return Err((
            StatusCode::BAD_REQUEST,
            "User presence flag not set".to_string(),
        ));
    }

    // Verify signature
    let client_data_hash = digest::digest(&digest::SHA256, &decoded_client_data);

    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&auth_data_bytes);
    signed_data.extend_from_slice(client_data_hash.as_ref());

    let signature = base64url_decode(&auth_data.response.signature).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to decode signature: {}", e),
        )
    })?;

    let credential = store
        .credentials
        .get(&auth_data.id)
        .ok_or((StatusCode::BAD_REQUEST, "Unknown credential".to_string()))?;

    let verification_algorithm = &ring::signature::ECDSA_P256_SHA256_ASN1;
    let public_key = UnparsedPublicKey::new(verification_algorithm, &credential.public_key);

    public_key
        .verify(&signed_data, &signature)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature".to_string()))?;

    store.challenges.remove(&auth_data.auth_id);
    Ok("Authentication successful")
}

#[tokio::main]
async fn main() {
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
