/// This module handles the authentication process using WebAuthn.
/// It provides routes for starting and verifying authentication.
///
/// The main components are:
/// - `router`: Sets up the routes for authentication.
/// - `start_authentication`: Initiates the authentication process by generating a challenge.
/// - `verify_authentication`: Verifies the authentication response from the client.
///
/// # Structures
/// - `AuthenticationOptions`: Represents the options for authentication.
/// - `AllowCredential`: Represents allowed credentials for authentication.
/// - `AuthenticateCredential`: Represents the credential data received from the client.
/// - `AuthenticatorAssertionResponse`: Represents the response from the authenticator.
///
/// # Functions
/// - `start_authentication`: Generates a challenge and returns authentication options.
/// - `verify_authentication`: Verifies the client's response to the authentication challenge.
///
/// # Errors
/// The functions return appropriate HTTP status codes and error messages in case of failures,
/// such as invalid client data, challenge verification failure, invalid origin, and invalid signature.
use axum::{
    extract::State,
    http::StatusCode,
    routing::{post, Router},
    Json,
};

use base64::engine::{general_purpose::URL_SAFE, Engine};
use ring::{digest, rand::SecureRandom, signature::UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::passkey::{base64url_decode, AppState, StoredChallenge};

pub(crate) fn router(state: AppState) -> Router {
    Router::new()
        .route("/start", post(start_authentication))
        .route(
            "/verify",
            post(|state, json| async move {
                match verify_authentication(state, json).await {
                    Ok(message) => (StatusCode::OK, message.to_string()),
                    Err((status, message)) => (status, message),
                }
            }),
        )
        .with_state(state)
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

    #[cfg(debug_assertions)]
    println!("Available credentials: {:?}", allow_credentials);

    let auth_option = AuthenticationOptions {
        challenge: URL_SAFE.encode(&challenge),
        timeout: 60000,
        rp_id: state.config.rp_id.clone(),
        allow_credentials,
        user_verification: "preferred".to_string(),
        auth_id,
    };

    #[cfg(debug_assertions)]
    println!("Auth options: {:?}", auth_option);
    Json(auth_option)
}

async fn verify_authentication(
    State(state): State<AppState>,
    Json(auth_data): Json<AuthenticateCredential>,
) -> Result<&'static str, (StatusCode, String)> {
    #[cfg(debug_assertions)]
    println!("Authenticating user: {:?}", auth_data);

    let mut store = state.store.lock().await;

    // Retrieve the stored challenge
    let stored_challenge = store.challenges.get(&auth_data.auth_id).ok_or((
        StatusCode::BAD_REQUEST,
        "No stored challenge for this auth_id".to_string(),
    ))?;

    #[cfg(debug_assertions)]
    println!(
        "Stored challenge: {:?}",
        URL_SAFE.encode(&stored_challenge.challenge)
    );

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

    #[cfg(debug_assertions)]
    println!("Client data: {:?}", client_data);

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
    let authenticator_data =
        base64url_decode(&auth_data.response.authenticator_data).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Failed to decode authenticator data: {}", e),
            )
        })?;

    let rp_id_hash = digest::digest(&digest::SHA256, state.config.rp_id.as_bytes());
    if authenticator_data[..32] != rp_id_hash.as_ref()[..] {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid RP ID hash in authenticator data".to_string(),
        ));
    }

    let flags = authenticator_data[32];
    if flags & 0x01 != 0x01 {
        return Err((
            StatusCode::BAD_REQUEST,
            "User presence flag not set".to_string(),
        ));
    }

    #[cfg(debug_assertions)]
    println!(
        "authenticator_data: {:?}",
        URL_SAFE.encode(&authenticator_data)
    );

    // Verify signature
    let client_data_hash = digest::digest(&digest::SHA256, &decoded_client_data);

    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&authenticator_data);
    signed_data.extend_from_slice(client_data_hash.as_ref());

    #[cfg(debug_assertions)]
    println!("Signed data: {:?}", URL_SAFE.encode(&signed_data));

    let signature = base64url_decode(&auth_data.response.signature).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to decode signature: {}", e),
        )
    })?;

    #[cfg(debug_assertions)]
    println!("Signature: {:?}", URL_SAFE.encode(&signature));

    let credential = store
        .credentials
        .get(&auth_data.id)
        .ok_or((StatusCode::BAD_REQUEST, "Unknown credential".to_string()))?;

    let verification_algorithm = &ring::signature::ECDSA_P256_SHA256_ASN1;
    let public_key = UnparsedPublicKey::new(verification_algorithm, &credential.public_key);

    #[cfg(debug_assertions)]
    println!("Public key: {:?}", URL_SAFE.encode(&credential.public_key));

    public_key
        .verify(&signed_data, &signature)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature".to_string()))?;

    store.challenges.remove(&auth_data.auth_id);
    Ok("Authentication successful")
}
