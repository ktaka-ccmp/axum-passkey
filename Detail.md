# WebAuthn Implementation Technical Reference

## PART 1: COMPONENT REFERENCE

### Core Data Structures

#### AuthStore
```rust
struct AuthStore {
    challenges: HashMap<String, StoredChallenge>,
    credentials: HashMap<String, StoredCredential>,
}
```
Purpose: Central in-memory storage for challenges and credentials.

- `challenges`: Maps challenge IDs to challenge data
  - For registration: key = username
  - For authentication: key = auth_id (UUID)
- `credentials`: Maps credential IDs to stored credentials
  - key = raw credential ID in base64url format
  - value = credential data including public key

#### StoredChallenge
```rust
struct StoredChallenge {
    challenge: Vec<u8>,    // 32 bytes of random data
    username: String,      // User identifier (empty for auth)
    timestamp: u64,        // UNIX timestamp of creation
}
```
Purpose: Maintains challenge state for ongoing operations.

- `challenge`: Random bytes used to prevent replay attacks
- `username`: Links challenge to specific registration attempt
- `timestamp`: Enables future expiry checking

#### StoredCredential
```rust
struct StoredCredential {
    credential_id: Vec<u8>,  // Raw credential identifier
    public_key: Vec<u8>,     // EC public key (65 bytes)
    counter: u32,            // For future signature counting
}
```
Purpose: Stores credential data for future authentication.

- `credential_id`: Raw bytes of the credential identifier
- `public_key`: Uncompressed EC public key (0x04 || x || y)
- `counter`: Reserved for signature count verification

### Registration Functions

#### start_registration
```rust
async fn start_registration(
    State(state): State<AppState>,
    Json(username): Json<String>,
) -> Json<RegistrationOptions>
```
Purpose: Initiates registration process for new user.

Steps:

1. Generates 32-byte random challenge
2. Creates StoredChallenge with username
3. Stores challenge in AuthStore
4. Returns RegistrationOptions including:
   - Challenge (base64url encoded)
   - RP ID and name
   - User information
   - Key parameters (ES256)
   - Authenticator preferences

Example data:
```rust
// Input
username = "alice"

// Generated challenge (before base64url)
challenge = [random 32 bytes]

// Output
{
    "challenge": "base64url...",
    "rp": {
        "name": "Passkey Demo",
        "id": "p3001.h.ccmp.jp"
    },
    "user": {
        "id": "uuid...",
        "name": "alice",
        "displayName": "alice"
    },
    "pubKeyCredParams": [{
        "type": "public-key",
        "alg": -7
    }],
    ...
}
```

Common issues:

- Username conflicts (no duplicate checking)
- Challenge storage failures
- RNG failures

#### finish_registration
```rust
async fn finish_registration(
    State(state): State<AppState>,
    Json(reg_data): Json<RegisterCredential>,
) -> Result<&'static str, (StatusCode, String)>
```
Purpose: Validates registration response and stores credential.

Processing steps:

1. Decodes and verifies client data
   - Checks origin matches configuration
   - Verifies operation type is "webauthn.create"
   - Validates challenge matches stored value

2. Processes attestation object
   ```rust
   attestation_object (CBOR Map)
   ├── fmt: "none" or "packed"
   ├── authData: bytes
   │   ├── rpIdHash (32 bytes)
   │   ├── flags (1 byte)
   │   ├── counter (4 bytes)
   │   └── attestedCredentialData
   │       ├── aaguid (16 bytes)
   │       ├── credentialIdLength (2 bytes)
   │       ├── credentialId (variable)
   │       └── credentialPublicKey (COSE_Key)
   └── attStmt: {}
   ```

3. Extracts public key:
   ```rust
   // COSE_Key format
   {
       1: 2,        // kty: EC2
       3: -7,       // alg: ES256
       -1: 1,       // crv: P-256
       -2: x_coord, // x-coordinate
       -3: y_coord  // y-coordinate
   }
   ```

4. Stores credential:
   - Uses raw_id as key
   - Stores public key in uncompressed format
   - Sets initial counter to 0

Error handling:

- Invalid client data format
- Challenge mismatch
- Unsupported attestation format
- Invalid credential format
- Storage failures

### Authentication Functions

#### start_authentication
```rust
async fn start_authentication(
    State(state): State<AppState>,
) -> Json<AuthenticationOptions>
```
Purpose: Initiates authentication process by creating challenge and listing available credentials.

Processing steps:

1. Generates new authentication challenge:

```rust
let mut challenge = vec![0u8; 32];
state.rng.fill(&mut challenge).unwrap();
```

2. Creates and stores authentication challenge:

```rust
let auth_id = Uuid::new_v4().to_string();
let stored_challenge = StoredChallenge {
    challenge: challenge.clone(),
    username: "".to_string(), // Empty for auth
    timestamp: std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs(),
};
store.challenges.insert(auth_id.clone(), stored_challenge);
```

3. Lists available credentials:

```rust
let allow_credentials: Vec<_> = store
    .credentials
    .keys()
    .map(|id| AllowCredential {
        type_: "public-key".to_string(),
        id: id.clone(),
    })
    .collect();
```

Output structure:
```json
{
    "challenge": "base64url...",
    "timeout": 60000,
    "rpId": "p3001.h.ccmp.jp",
    "allowCredentials": [
        {
            "type": "public-key",
            "id": "credential_id_in_base64url"
        }
    ],
    "userVerification": "preferred",
    "auth_id": "uuid..."
}
```

Important fields:

- `challenge`: Fresh random challenge encoded in base64url
- `allowCredentials`: List of previously registered credentials
- `auth_id`: UUID for tracking this authentication attempt
- `rpId`: Domain for which credentials are valid

#### verify_authentication
```rust
async fn verify_authentication(
    State(state): State<AppState>,
    Json(auth_data): Json<AuthenticateCredential>,
) -> Result<&'static str, (StatusCode, String)>
```
Purpose: Verifies authentication response including signature verification.

Input structure:
```rust
struct AuthenticateCredential {
    id: String,          // Credential identifier
    raw_id: String,      // Base64URL credential bytes
    response: AuthenticatorAssertionResponse {
        authenticator_data: String,  // Base64URL auth data
        client_data_json: String,    // Base64URL client data
        signature: String,           // Base64URL signature
    },
    auth_id: String,     // Challenge identifier
}
```

Verification steps:

1. Challenge verification:

```rust
// Retrieve stored challenge
let stored_challenge = store.challenges.get(&auth_data.auth_id)?;

// Verify challenge in client data matches
let challenge_str = client_data["challenge"].as_str()?;
let decoded_challenge = base64url_decode(challenge_str)?;
if decoded_challenge != stored_challenge.challenge {
    return Err(...);
}
```

2. Client data verification:

```rust
// Origin check
if client_data["origin"] != state.config.origin {
    return Err(...);
}

// Operation type check
if client_data["type"] != "webauthn.get" {
    return Err(...);
}
```

3. Authenticator data verification:

```rust
let auth_data_bytes = base64url_decode(&auth_data.response.authenticator_data)?;

// RP ID hash check
let rp_id_hash = digest::digest(&digest::SHA256, state.config.rp_id.as_bytes());
if auth_data_bytes[..32] != rp_id_hash.as_ref()[..] {
    return Err(...);
}

// User presence flag check
let flags = auth_data_bytes[32];
if flags & 0x01 != 0x01 {
    return Err(...);
}
```

4. Signature verification:

```rust
// Build signed data
let client_data_hash = digest::digest(&digest::SHA256, &decoded_client_data);
let mut signed_data = Vec::new();
signed_data.extend_from_slice(&auth_data_bytes);
signed_data.extend_from_slice(client_data_hash.as_ref());

// Get credential
let credential = store.credentials.get(&auth_data.id)?;

// Verify signature
let verification_algorithm = &ring::signature::ECDSA_P256_SHA256_ASN1;
let public_key = UnparsedPublicKey::new(verification_algorithm, &credential.public_key);
public_key.verify(&signed_data, &signature)?;
```

Common error scenarios:

1. Challenge mismatch
   - Expired challenge
   - Wrong challenge used
   - Challenge replay attempt

2. Credential lookup failure
   - Unknown credential ID
   - Corrupted credential data
   - Credential storage issues

3. Signature verification failure
   - Corrupted signature
   - Wrong public key
   - Data tampering

### Attestation Verification

#### verify_packed_attestation
```rust
fn verify_packed_attestation(
    auth_data: &[u8],
    client_data_hash: &[u8],
    att_stmt: &Vec<(CborValue, CborValue)>,
) -> Result<(), String>
```
Purpose: Verifies packed attestation format including certificate chain.

Steps:

1. Extract signature and algorithm:

```rust
let (alg, sig) = get_sig_from_stmt(att_stmt)?;
if alg != -7 {  // ES256
    return Err(...);
}
```

2. Build verification data:

```rust
let mut verify_data = Vec::new();
verify_data.extend_from_slice(auth_data);
verify_data.extend_from_slice(client_data_hash);
```

3. Extract and verify certificate:

```rust
// Get x5c certificate chain
let x5c_bytes = x5c_opt.ok_or_else(|| 
    "No x5c array found in attStmt for 'packed'"
)?;

// Parse certificate
let cert = EndEntityCert::try_from(x5c_bytes.as_ref())?;

// Verify signature
cert.verify_signature(
    &webpki::ECDSA_P256_SHA256,
    &verify_data,
    &sig
)?;
```

## PART 2: OPERATION FLOWS

### Registration Flow

1. Client Initiates Registration

```javascript
// Client sends username
POST /register/start
Body: "username"
```

2. Server Creates Registration Options

```rust
// Server generates challenge
let mut challenge = vec![0u8; 32];
state.rng.fill(&mut challenge);

// Stores challenge with username
store.challenges.insert(username.clone(), StoredChallenge {...});

// Returns registration options
Json(RegistrationOptions {...})
```

3. Client Creates Credential

```javascript
// Client requests credential from authenticator
const credential = await navigator.credentials.create({
    publicKey: {
        // Convert challenge to Uint8Array
        challenge: base64URLToUint8Array(options.challenge),
        
        // User info
        user: {
            id: new TextEncoder().encode(options.user.id),
            name: options.user.name,
            displayName: options.user.displayName
        },
        
        // Other options from server
        rp: options.rp,
        pubKeyCredParams: options.pubKeyCredParams,
        ...
    }
});

// Format response for server
const credentialResponse = {
    id: credential.id,
    raw_id: arrayBufferToBase64URL(credential.rawId),
    type: credential.type,
    response: {
        attestation_object: arrayBufferToBase64URL(
            credential.response.attestationObject
        ),
        client_data_json: arrayBufferToBase64URL(
            credential.response.clientDataJSON
        )
    },
    username: username
};
```

4. Server Verifies Registration

```rust
// Verification chain:

// a. Client Data Verification
let client_data: serde_json::Value = serde_json::from_str(&client_data_str)?;
verify_client_data(&client_data, &state.config, "webauthn.create")?;

// b. Challenge Verification
let stored_challenge = store.challenges.get(&reg_data.username)?;
verify_challenge(&decoded_challenge, &stored_challenge.challenge)?;

// c. Attestation Object Processing
let attestation_cbor: CborValue = parse_cbor(&attestation_object)?;
let (fmt, auth_data, att_stmt) = extract_attestation_data(&attestation_cbor)?;

// d. Attestation Verification
match fmt.as_str() {
    "none" => { /* Trust the attestation */ },
    "packed" => {
        verify_packed_attestation(
            &auth_data,
            client_data_hash.as_ref(),
            &att_stmt
        )?;
    },
    _ => return Err(...)
}

// e. Credential Data Extraction
let credential_data = extract_credential_data(&auth_data)?;
let public_key = extract_public_key(&credential_data)?;

// f. Credential Storage
store.credentials.insert(
    reg_data.raw_id.clone(),
    StoredCredential {
        credential_id,
        public_key,
        counter: 0,
    }
);
```

### Authentication Flow

1. Client Requests Authentication

```javascript
// Client initiates authentication
POST /auth/start
// No body needed
```

2. Server Prepares Authentication Options

```rust
// Server side preparation
let auth_id = Uuid::new_v4().to_string();
let challenge = generate_challenge();

// Store challenge for verification
store.challenges.insert(auth_id.clone(), StoredChallenge {
    challenge: challenge.clone(),
    username: "".to_string(),
    timestamp: current_time(),
});

// List available credentials
let allow_credentials = store.credentials
    .keys()
    .map(|id| AllowCredential {...})
    .collect();

// Return options to client
Json(AuthenticationOptions {
    challenge: base64url_encode(&challenge),
    allow_credentials,
    auth_id,
    ...
})
```

3. Client Gets Assertion

```javascript
// Request assertion from authenticator
const credential = await navigator.credentials.get({
    publicKey: {
        challenge: base64URLToUint8Array(options.challenge),
        allowCredentials: options.allowCredentials.map(cred => ({
            type: cred.type,
            id: base64URLToUint8Array(cred.id),
        })),
        ...
    }
});

// Format response for server
const authResponse = {
    id: credential.id,
    raw_id: arrayBufferToBase64URL(credential.rawId),
    type: credential.type,
    response: {
        authenticator_data: arrayBufferToBase64URL(
            credential.response.authenticatorData
        ),
        client_data_json: arrayBufferToBase64URL(
            credential.response.clientDataJSON
        ),
        signature: arrayBufferToBase64URL(
            credential.response.signature
        )
    },
    auth_id: options.authId
};
```

4. Server Verifies Authentication

```rust
// Verification chain:

// a. Get Stored Challenge
let stored_challenge = store.challenges.get(&auth_data.auth_id)?;

// b. Verify Client Data
let client_data = parse_and_verify_client_data(
    &auth_data.response.client_data_json,
    &state.config,
    "webauthn.get"
)?;

// c. Verify Challenge
verify_challenge_matches(
    &client_data,
    &stored_challenge.challenge
)?;

// d. Verify Authenticator Data
let auth_data_bytes = verify_authenticator_data(
    &auth_data.response.authenticator_data,
    &state.config.rp_id
)?;

// e. Verify Signature
let credential = store.credentials.get(&auth_data.id)?;
verify_signature(
    &auth_data_bytes,
    &client_data_hash,
    &credential.public_key,
    &signature
)?;
```

### Important Security Considerations

1. Challenge Management

```rust
// Challenges must be:
// - Random (32 bytes from secure RNG)
// - Single-use (removed after verification)
// - Time-limited (check timestamp)
// - Bound to operation type (create/get)
```

2. Credential Storage

```rust
// Credentials should:
// - Use consistent ID format
// - Store raw public key safely
// - Maintain authenticator counter
// - Link to user identity
```

3. Common Attack Vectors

- Replay attacks (mitigated by challenge)
- Origin forgery (checked in client data)
- Credential ID tampering (verified by signature)
- RP ID mismatch (checked in authenticator data)

4. Error Cases to Handle

```rust
// Registration errors:
- Invalid attestation format
- Unsupported algorithm
- Challenge mismatch
- Origin mismatch
- Certificate validation failure

// Authentication errors:
- Unknown credential
- Invalid signature
- Counter replay
- Challenge timeout
- User verification failure
```
