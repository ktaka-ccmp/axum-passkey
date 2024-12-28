use axum::{
    extract::State,
    http::StatusCode,
    routing::{post, Router},
    Json,
};

use base64::engine::{general_purpose::URL_SAFE, Engine};
use ciborium::value::{Integer, Value as CborValue};
use ring::{digest, rand::SecureRandom};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::passkey::{base64url_decode, StoredChallenge, StoredCredential};
use crate::AppState;

pub(crate) fn router(state: AppState) -> Router {
    Router::new()
        .route("/start", post(start_registration))
        .route(
            "/finish",
            post(|state, json| async move {
                match finish_registration(state, json).await {
                    Ok(message) => (StatusCode::OK, message.to_string()),
                    Err((status, message)) => (status, message),
                }
            }),
        )
        .with_state(state)
}

#[derive(Serialize, Debug)]
struct PublicKeyCredentialUserEntity {
    id: String,
    name: String,
    #[serde(rename = "displayName")]
    display_name: String,
}

#[derive(Serialize, Debug)]
struct PubKeyCredParam {
    #[serde(rename = "type")]
    type_: String,
    alg: i32,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AuthenticatorSelection {
    authenticator_attachment: Option<String>,
    resident_key: String,
    user_verification: String,
}

#[derive(Serialize, Debug)]
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

#[derive(Serialize, Debug)]
struct RelyingParty {
    name: String,
    id: String,
}

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

    let options = RegistrationOptions {
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
    };

    #[cfg(not(debug_assertions))]
    println!("Debugging disabled");

    #[cfg(debug_assertions)]
    println!("Registration options: {:?}", options);

    Json(options)
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
            crate::passkey::attestation::verify_packed_attestation(
                &auth_data,
                client_data_hash.as_ref(),
                &att_stmt,
            )
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Attestation verification failed: {:?}", e),
                )
            })?;
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
