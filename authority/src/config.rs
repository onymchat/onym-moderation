//! Environment-driven configuration.

use std::env;

use crate::types::AuthorityManifest;

pub struct Config {
    pub bind_addr: String,
    pub store_path: String,

    /// The manifest's exact published bytes. Served verbatim at
    /// `/manifest.json` and shipped with every verdict, because the
    /// user's mandate pins their SHA-256 — re-serializing a parsed
    /// manifest would produce different bytes and break that pin.
    pub manifest_raw: Vec<u8>,
    pub manifest: AuthorityManifest,

    /// Ed25519 seed for the verdict-signing key. §8 obligation 9 says
    /// to operate this separately from operational keys; here that
    /// means it is its own env var and belongs in its own secret store.
    pub signing_seed: [u8; 32],

    /// Where to deliver verdicts, and the token that endpoint expects.
    pub interface_base_url: Option<String>,
    pub interface_token: Option<String>,
    /// The interface's countersigning key, used to check that a
    /// registered mandate really was countersigned by the interface
    /// that claims to have witnessed it.
    pub interface_key: Option<String>,

    /// Bearer token for the moderator's decision endpoint. Deciding a
    /// case is the authority's judgment; nothing here should be able to
    /// decide one without it.
    pub moderator_token: Option<String>,

    pub deadline_sweep_secs: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let bind_addr = env::var("AUTHORITY_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
        let store_path =
            env::var("AUTHORITY_STORE_PATH").unwrap_or_else(|_| "/data/authority.sqlite".into());

        let manifest_path = env::var("AUTHORITY_MANIFEST_PATH")
            .map_err(|_| "AUTHORITY_MANIFEST_PATH is required".to_string())?;
        let manifest_raw = std::fs::read(&manifest_path)
            .map_err(|e| format!("AUTHORITY_MANIFEST_PATH {manifest_path}: {e}"))?;
        let manifest: AuthorityManifest = serde_json::from_slice(&manifest_raw)
            .map_err(|e| format!("{manifest_path} is not a valid authority manifest: {e}"))?;
        manifest
            .validate_class_terms()
            .map_err(|e| format!("{manifest_path} has invalid authority policy: {e}"))?;

        let signing_seed = match env::var("AUTHORITY_SIGNING_SEED") {
            Ok(hex_seed) => {
                let raw = hex::decode(hex_seed.trim())
                    .map_err(|_| "AUTHORITY_SIGNING_SEED must be hex".to_string())?;
                let seed: [u8; 32] = raw.try_into().map_err(|_| {
                    "AUTHORITY_SIGNING_SEED must be 32 bytes (64 hex chars)".to_string()
                })?;
                seed
            }
            Err(_) => return Err("AUTHORITY_SIGNING_SEED is required".into()),
        };

        Ok(Self {
            bind_addr,
            store_path,
            manifest_raw,
            manifest,
            signing_seed,
            interface_base_url: env::var("AUTHORITY_INTERFACE_URL").ok().filter(|v| !v.is_empty()),
            interface_token: env::var("AUTHORITY_INTERFACE_TOKEN").ok().filter(|v| !v.is_empty()),
            interface_key: env::var("AUTHORITY_INTERFACE_KEY").ok().filter(|v| !v.is_empty()),
            moderator_token: env::var("AUTHORITY_MODERATOR_TOKEN").ok().filter(|v| !v.is_empty()),
            deadline_sweep_secs: env::var("AUTHORITY_DEADLINE_SWEEP_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
        })
    }

    pub fn usage() -> &'static str {
        r#"Required:
  AUTHORITY_MANIFEST_PATH      Path to this authority's published manifest.json.
                               Served verbatim; the bytes are what users' mandates pin.
  AUTHORITY_SIGNING_SEED       32-byte hex seed for the verdict-signing key
                               (generate: openssl rand -hex 32). Keep it separate from
                               operational secrets, and never rotate it while bans run —
                               verdicts already issued would stop verifying.

Delivering verdicts to the interface:
  AUTHORITY_INTERFACE_URL      Base URL of the enforcement backend (e.g.
                               https://moderation.onym.app)
  AUTHORITY_INTERFACE_TOKEN    Its MODERATION_AUTHORITY_TOKEN
  AUTHORITY_INTERFACE_KEY      onym:key:<hex> of the interface's countersigning key,
                               used to check registered mandates were really countersigned

Optional:
  AUTHORITY_BIND               Listen address (default: 0.0.0.0:8080)
  AUTHORITY_STORE_PATH         SQLite path (default: /data/authority.sqlite)
  AUTHORITY_MODERATOR_TOKEN    Bearer token for POST /v1/cases/:id/decide.
                               Unset closes the endpoint — nothing may decide a case.
  AUTHORITY_DEADLINE_SWEEP_SECS  How often to dismiss overdue cases (default: 300)
"#
    }
}
