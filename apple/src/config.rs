//! Environment-driven configuration, in the shape onym-relayer uses:
//! everything from env vars, validated once at boot with a usage
//! message rather than failing later at first request.

use std::env;

use crate::devicecheck::Environment;

pub struct Config {
    pub bind_addr: String,
    pub store_path: String,

    /// Apple DeviceCheck credentials. Absent in `--dry-run`-style
    /// deployments, where the gate can still answer from stored verdict
    /// state but must never claim a device is clean (see
    /// `Config::device_check_configured`).
    pub p8_pem: Option<Vec<u8>>,
    pub key_id: Option<String>,
    pub team_id: Option<String>,
    pub environment: Environment,

    /// Ed25519 seed for the interface's countersigning key, hex.
    pub interface_signing_seed: [u8; 32],
    /// This interface's component id, carried in mandates.
    pub interface_component_id: String,

    /// Reject verdicts whose authority signature doesn't verify.
    /// Mirrors `ModerationTrust.enforceVerdictSignatures` on the
    /// client: default off until authorities publish signing keys, and
    /// MUST be on in production.
    pub enforce_signatures: bool,

    /// Shared secret an authority presents on `POST /v1/verdicts`.
    /// Transport-level authentication only — the verdict's own
    /// signature is what actually authorizes a mark.
    pub authority_token: Option<String>,

    /// Explicit opt-out from requiring `authority_token`. Absent it,
    /// an unset token fails closed: an open verdict endpoint is an
    /// unauthenticated write into the store, and "degraded toward
    /// blocking" is the stance everywhere else here.
    pub allow_unauthenticated_authority: bool,

    /// Bearer token for `GET /v1/write-log`. The log names every
    /// device binding, verdict, and mark transition, so it is not
    /// public. No token means the endpoint is closed.
    pub audit_token: Option<String>,

    /// How far a signed session timestamp may be from our clock before
    /// the request is refused, in seconds.
    pub session_max_skew_secs: i64,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let bind_addr = env::var("MODERATION_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
        let store_path =
            env::var("MODERATION_STORE_PATH").unwrap_or_else(|_| "/data/moderation.sqlite".into());

        // The .p8 may arrive as a path (compose secret/volume) or
        // inline (env var), because deployment shapes differ.
        let p8_pem = match env::var("MODERATION_DEVICECHECK_KEY_PATH") {
            Ok(path) => Some(
                std::fs::read(&path)
                    .map_err(|e| format!("MODERATION_DEVICECHECK_KEY_PATH {path}: {e}"))?,
            ),
            Err(_) => env::var("MODERATION_DEVICECHECK_KEY_PEM")
                .ok()
                .map(|pem| pem.replace("\\n", "\n").into_bytes()),
        };
        let key_id = env::var("MODERATION_DEVICECHECK_KEY_ID").ok();
        let team_id = env::var("MODERATION_DEVICECHECK_TEAM_ID").ok();
        let environment = Environment::parse(
            &env::var("MODERATION_DEVICECHECK_ENV").unwrap_or_else(|_| "production".into()),
        )?;

        let interface_signing_seed = match env::var("MODERATION_INTERFACE_SIGNING_SEED") {
            Ok(hex_seed) => {
                let raw = hex::decode(hex_seed.trim())
                    .map_err(|_| "MODERATION_INTERFACE_SIGNING_SEED must be hex".to_string())?;
                let seed: [u8; 32] = raw.try_into().map_err(|_| {
                    "MODERATION_INTERFACE_SIGNING_SEED must be 32 bytes (64 hex chars)".to_string()
                })?;
                seed
            }
            Err(_) => return Err("MODERATION_INTERFACE_SIGNING_SEED is required".into()),
        };

        let interface_component_id = env::var("MODERATION_INTERFACE_COMPONENT_ID")
            .unwrap_or_else(|_| "onym:component:onym-ios".into());

        let enforce_signatures = env::var("MODERATION_ENFORCE_SIGNATURES")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let authority_token = env::var("MODERATION_AUTHORITY_TOKEN").ok().filter(|t| !t.is_empty());
        let allow_unauthenticated_authority = env::var("MODERATION_ALLOW_UNAUTHENTICATED_AUTHORITY")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        let audit_token = env::var("MODERATION_AUDIT_TOKEN").ok().filter(|t| !t.is_empty());
        let session_max_skew_secs = env::var("MODERATION_SESSION_MAX_SKEW_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);

        Ok(Self {
            bind_addr,
            store_path,
            p8_pem,
            key_id,
            team_id,
            environment,
            interface_signing_seed,
            interface_component_id,
            enforce_signatures,
            authority_token,
            allow_unauthenticated_authority,
            audit_token,
            session_max_skew_secs,
        })
    }

    pub fn device_check_configured(&self) -> bool {
        self.p8_pem.is_some() && self.key_id.is_some() && self.team_id.is_some()
    }

    pub fn usage() -> &'static str {
        r#"Required:
  MODERATION_INTERFACE_SIGNING_SEED   32-byte hex seed for the interface's Ed25519
                                      countersigning key (generate: openssl rand -hex 32)

Apple DeviceCheck (required to read or write device marks; without
these the gate never answers "clear"):
  MODERATION_DEVICECHECK_KEY_PATH     Path to AuthKey_<KEYID>.p8
  MODERATION_DEVICECHECK_KEY_PEM      ...or the PEM inline (\n-escaped)
  MODERATION_DEVICECHECK_KEY_ID       10-character key id
  MODERATION_DEVICECHECK_TEAM_ID      10-character Apple team id
  MODERATION_DEVICECHECK_ENV          production | development (default: production)

Optional:
  MODERATION_BIND                     Listen address (default: 0.0.0.0:8080)
  MODERATION_STORE_PATH               SQLite path (default: /data/moderation.sqlite)
  MODERATION_INTERFACE_COMPONENT_ID   Default: onym:component:onym-ios
  MODERATION_ENFORCE_SIGNATURES       true to reject unverifiable verdict signatures
                                      (default: false — MUST be true in production)
  MODERATION_AUTHORITY_TOKEN          Bearer token an authority presents on POST /v1/verdicts.
                                      Required: without it the endpoint refuses every request
                                      unless MODERATION_ALLOW_UNAUTHENTICATED_AUTHORITY=true
  MODERATION_AUDIT_TOKEN              Bearer token for GET /v1/write-log. Unset closes the
                                      endpoint — the log names devices, verdicts, and marks
  MODERATION_SESSION_MAX_SKEW_SECS    Freshness window for signed session timestamps
                                      (default: 300)
"#
    }
}
