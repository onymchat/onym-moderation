//! Environment-driven configuration.

use std::env;

use crate::profiles::{self, ModelProfile};
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

    /// Triage configuration. `None` means no classifier runs at all.
    pub triage: Option<TriageConfig>,

    /// Bearer token for the moderator web panel. The panel shows
    /// disclosed evidence, so an unset token closes it.
    pub admin_token: Option<String>,
}

/// How much authority a classifier has over a case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriageMode {
    /// Classify and attach a recommendation; a human decides.
    Advisory,
    /// Classify and decide. Still bound by every guard in
    /// `decisions.rs` — notably, no ban before the response window.
    Autonomous,
}

#[derive(Debug)]
pub struct TriageConfig {
    pub mode: TriageMode,
    /// The inference endpoint. Defaults to a sibling container because
    /// the model is meant to run on this host: case evidence is content
    /// a reporter disclosed for adjudication, and shipping it to
    /// someone else's API is a disclosure of its own — and, under the
    /// reference policy, one that requires fresh consent.
    pub url: String,
    pub api_key: Option<String>,
    /// The consented model profile. Prompt, output parsing, thresholds
    /// and category mapping all come from here rather than from
    /// environment variables, because they are terms a user agreed to
    /// and not settings an operator retunes between cases.
    pub profile: ModelProfile,
    pub timeout_secs: u64,
}

impl TriageConfig {
    fn from_env() -> Result<Option<Self>, String> {
        let mode = match env::var("AUTHORITY_TRIAGE_MODE").unwrap_or_else(|_| "off".into()).as_str() {
            "off" => return Ok(None),
            "advisory" => TriageMode::Advisory,
            "autonomous" => TriageMode::Autonomous,
            other => {
                return Err(format!(
                    "AUTHORITY_TRIAGE_MODE {other:?} is not off | advisory | autonomous"
                ))
            }
        };

        // Either a published reference profile by id, or a profile
        // document of your own. The second is the point: this service is
        // not tied to the six models anyone happened to write up.
        let mut profile = match (
            env::var("AUTHORITY_TRIAGE_PROFILE").ok().filter(|v| !v.is_empty()),
            env::var("AUTHORITY_TRIAGE_PROFILE_PATH").ok().filter(|v| !v.is_empty()),
        ) {
            (Some(_), Some(_)) => {
                return Err("set AUTHORITY_TRIAGE_PROFILE or AUTHORITY_TRIAGE_PROFILE_PATH, not \
                            both — two profiles is two sets of terms"
                    .into())
            }
            (Some(id), None) => profiles::by_id(&id).ok_or_else(|| {
                format!(
                    "AUTHORITY_TRIAGE_PROFILE {id:?} is not a published profile. Known: {}. \
                     For any other model, describe it in a JSON profile and set \
                     AUTHORITY_TRIAGE_PROFILE_PATH.",
                    profiles::builtin_ids().join(", ")
                )
            })?,
            (None, Some(path)) => {
                let raw = std::fs::read(&path)
                    .map_err(|e| format!("AUTHORITY_TRIAGE_PROFILE_PATH {path}: {e}"))?;
                serde_json::from_slice::<ModelProfile>(&raw)
                    .map_err(|e| format!("{path} is not a valid model profile: {e}"))?
            }
            (None, None) => {
                return Err(format!(
                    "AUTHORITY_TRIAGE_MODE is set but no profile is. Set \
                     AUTHORITY_TRIAGE_PROFILE to one of: {}, or AUTHORITY_TRIAGE_PROFILE_PATH to \
                     your own. There is no default: which model decides a case is a term users \
                     consent to, not something to inherit silently.",
                    profiles::builtin_ids().join(", ")
                ))
            }
        };

        // The one field a deployment legitimately overrides: local
        // servers name loaded models however they were started, and
        // that name is not part of anyone's consent.
        if let Ok(served) = env::var("AUTHORITY_TRIAGE_SERVED_MODEL") {
            if !served.is_empty() {
                profile.served_model = served;
            }
        }

        let url = env::var("AUTHORITY_TRIAGE_URL")
            .unwrap_or_else(|_| "http://moderation-model:8000/v1/chat/completions".into());

        Ok(Some(Self {
            mode,
            url,
            api_key: env::var("AUTHORITY_TRIAGE_API_KEY").ok().filter(|v| !v.is_empty()),
            profile,
            timeout_secs: env::var("AUTHORITY_TRIAGE_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(120),
        }))
    }
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
            triage: TriageConfig::from_env()?,
            admin_token: env::var("AUTHORITY_ADMIN_TOKEN").ok().filter(|v| !v.is_empty()),
        })
    }

    /// Whether evidence would leave this host to be classified.
    ///
    /// The check is deliberately crude — loopback and RFC 1918 are
    /// "here", everything else is "somewhere else". A classifier
    /// reachable at a public address means recipient-disclosed
    /// evidence travels to a third party, which is a confidentiality
    /// change the manifest has to declare (§8 obligation 6), not a
    /// deployment detail.
    pub fn triage_leaves_this_host(triage: &TriageConfig) -> bool {
        let host = triage
            .url
            .split("://")
            .nth(1)
            .unwrap_or(&triage.url)
            .split('/')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("");
        !(host == "localhost"
            || host == "127.0.0.1"
            || host == "::1"
            || host == "[::1]"
            // Compose service names resolve on the private network.
            || !host.contains('.')
            || host.starts_with("10.")
            || host.starts_with("192.168.")
            || host.starts_with("172.16.")
            || host.starts_with("172.17.")
            || host.starts_with("172.18.")
            || host.starts_with("172.19.")
            || host.starts_with("172.2")
            || host.starts_with("172.30.")
            || host.starts_with("172.31."))
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
  AUTHORITY_DEADLINE_SWEEP_SECS  How often to dismiss overdue cases, and assess cases
                               whose response window has closed (default: 300)
  AUTHORITY_ADMIN_TOKEN        Bearer token for the moderator panel at /admin, where
                               appeals are reviewed. Unset closes it.

Automated assessment (a model decides; a human reviews on appeal):
  AUTHORITY_TRIAGE_MODE        off | advisory | autonomous (default: off)
  AUTHORITY_TRIAGE_PROFILE     Which model, and with it the prompt, output parsing,
                               thresholds and category mapping. One of:
                                 shieldstral-3b, gpt-oss-safeguard-20b, qwen3guard-8b,
                                 nemotron-3.5-content-safety-4b, llama-guard-4-12b,
                                 shieldgemma-9b
                               No default: which model decides a case is a term users
                               consent to, not something to inherit silently.
  AUTHORITY_TRIAGE_PROFILE_PATH  ...or a profile of your own, as JSON. Set one or the
                               other, never both.
  AUTHORITY_TRIAGE_URL         OpenAI-compatible chat-completions endpoint, on this host
                               (default: http://moderation-model:8000/v1/chat/completions)
  AUTHORITY_TRIAGE_SERVED_MODEL  What your inference server calls the loaded model, if it
                               differs from the profile's default. The only triage value
                               a deployment overrides — thresholds and prompts are
                               consented policy and live in the profile.
  AUTHORITY_TRIAGE_API_KEY     Only if the local server requires one
  AUTHORITY_TRIAGE_TIMEOUT_SECS  Inference timeout (default: 120)
"#
    }
}
