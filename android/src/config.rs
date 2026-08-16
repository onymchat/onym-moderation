//! Environment-driven configuration, in the shape onym-relayer uses:
//! everything from env vars, validated once at boot with a usage
//! message rather than failing later at first request.

use std::env;

use crate::google_auth::ServiceAccountKey;

pub struct Config {
    pub bind_addr: String,
    pub store_path: String,

    /// Google Cloud service-account key for the Play Integrity API.
    /// Absent in `--dry-run`-style deployments, where the gate can
    /// still answer from stored verdict state but must never claim a
    /// device is clean (see `Config::play_configured`).
    pub play_sa_key: Option<ServiceAccountKey>,
    /// The app's package name — both API URLs and the classifier's
    /// package checks use it.
    pub play_package_name: Option<String>,
    /// Accepted signing-certificate SHA-256 digests, exactly as Google
    /// spells them in `certificateSha256Digest`.
    pub play_cert_sha256_digests: Vec<String>,
    /// Freshness window for a token's `requestDetails.timestampMillis`.
    pub play_token_max_age_secs: i64,
    /// Whether the gate refuses tokens without a deviceRecall object
    /// (the strict profile). See MODERATION_REQUIRE_RECALL above.
    pub require_recall: bool,

    /// How long an issued challenge stays presentable, seconds.
    pub challenge_ttl_secs: i64,
    /// How long after an accepted write a stale read is attributed to
    /// Google's up-to-30s write-to-read propagation lag.
    pub propagation_grace_secs: i64,

    /// Ed25519 seed for the interface's countersigning key, hex.
    pub interface_signing_seed: [u8; 32],
    /// Per-authority countersigning epochs. An authority absent here
    /// is on epoch 0, which is the root seed itself — rotation is
    /// opt-in per relationship rather than a global event.
    pub interface_key_epochs: std::collections::BTreeMap<String, u32>,
    /// This interface's component id, carried in mandates.
    pub interface_component_id: String,

    /// Reject verdicts whose authority signature doesn't verify.
    /// Default off until authorities publish signing keys, and MUST be
    /// on in production.
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

        // The key may arrive as a path (compose secret/volume) or
        // inline (env var), because deployment shapes differ.
        //
        // A path that does not exist is NOT fatal: docker-compose
        // always sets MODERATION_PLAY_SA_KEY_PATH, so treating the
        // missing secret as a boot error would turn "deploy without
        // the key, run degraded, every gate answers checkRequired" —
        // the behavior the README and deploy script promise — into a
        // restart crash-loop. A file that exists but will not read or
        // parse still fails loudly below: that is a real
        // misconfiguration, not an intentionally keyless deployment.
        let play_sa_raw = match env::var("MODERATION_PLAY_SA_KEY_PATH") {
            Ok(path) if std::path::Path::new(&path).exists() => Some(
                std::fs::read(&path)
                    .map_err(|e| format!("MODERATION_PLAY_SA_KEY_PATH {path}: {e}"))?,
            ),
            Ok(path) => {
                tracing::warn!(
                    %path,
                    "MODERATION_PLAY_SA_KEY_PATH does not exist — running without Play \
                     credentials; every gate check will answer checkRequired"
                );
                env::var("MODERATION_PLAY_SA_KEY_JSON").ok().map(String::into_bytes)
            }
            Err(_) => env::var("MODERATION_PLAY_SA_KEY_JSON").ok().map(String::into_bytes),
        };
        let play_sa_key = play_sa_raw
            .map(|raw| ServiceAccountKey::from_json(&raw))
            .transpose()?;
        let play_package_name = env::var("MODERATION_PLAY_PACKAGE_NAME").ok().filter(|v| !v.is_empty());
        let play_cert_sha256_digests: Vec<String> = env::var("MODERATION_PLAY_CERT_SHA256_DIGESTS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
            .collect();
        let play_token_max_age_secs = parse_secs("MODERATION_PLAY_TOKEN_MAX_AGE_SECS", 600)?;
        // INTERIM, pre-device-recall-grant: "false" lets the GATE
        // tolerate an absent deviceRecall object (prerequisites 1-4
        // still enforced) instead of answering checkRequired to every
        // device on Earth. Default TRUE — the strict profile — and
        // flipped back the day Google's grant lands. See
        // classifier::classify_enrollment for the enrollment-side
        // rationale this extends, and the README's disclosure.
        let require_recall = env::var("MODERATION_REQUIRE_RECALL")
            .map(|v| !(v == "false" || v == "0"))
            .unwrap_or(true);
        let challenge_ttl_secs = parse_secs("MODERATION_CHALLENGE_TTL_SECS", 600)?;
        let propagation_grace_secs = parse_secs("MODERATION_PROPAGATION_GRACE_SECS", 60)?;

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

        // Which countersigning key each authority expects. Absent
        // means epoch 0, the un-rotated root — so an existing
        // deployment needs no entry and nothing changes for it.
        let interface_key_epochs = crate::countersigning::parse_epochs(
            &env::var("MODERATION_INTERFACE_KEY_EPOCHS").unwrap_or_default(),
        )?;

        let interface_component_id = env::var("MODERATION_INTERFACE_COMPONENT_ID")
            .unwrap_or_else(|_| "onym:component:onym-android".into());

        let enforce_signatures = env::var("MODERATION_ENFORCE_SIGNATURES")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let authority_token = env::var("MODERATION_AUTHORITY_TOKEN").ok().filter(|t| !t.is_empty());
        let allow_unauthenticated_authority = env::var("MODERATION_ALLOW_UNAUTHENTICATED_AUTHORITY")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        let audit_token = env::var("MODERATION_AUDIT_TOKEN").ok().filter(|t| !t.is_empty());
        let session_max_skew_secs = parse_secs("MODERATION_SESSION_MAX_SKEW_SECS", 300)?;

        Ok(Self {
            bind_addr,
            store_path,
            play_sa_key,
            play_package_name,
            play_cert_sha256_digests,
            play_token_max_age_secs,
            require_recall,
            challenge_ttl_secs,
            propagation_grace_secs,
            interface_signing_seed,
            interface_key_epochs,
            interface_component_id,
            enforce_signatures,
            authority_token,
            allow_unauthenticated_authority,
            audit_token,
            session_max_skew_secs,
        })
    }

    /// Whether the deployment can reach the Play Integrity API at all.
    /// The certificate digests are part of the answer: a classifier
    /// with no expected digest would refuse every token anyway.
    pub fn play_configured(&self) -> bool {
        self.play_sa_key.is_some()
            && self.play_package_name.is_some()
            && !self.play_cert_sha256_digests.is_empty()
    }

    pub fn usage() -> &'static str {
        r#"Required:
  MODERATION_INTERFACE_SIGNING_SEED    32-byte hex seed for the interface's Ed25519
                                       countersigning key (generate: openssl rand -hex 32)

Google Play Integrity (required to read or write device marks; without
these the gate never answers "clear"):
  MODERATION_PLAY_SA_KEY_PATH          Path to the service-account JSON key of the
                                       Cloud project linked in the Play Console
  MODERATION_PLAY_SA_KEY_JSON          ...or the JSON inline
  MODERATION_PLAY_PACKAGE_NAME         The app's package name (e.g. app.onym.android)
  MODERATION_PLAY_CERT_SHA256_DIGESTS  Comma-separated accepted signing-certificate
                                       SHA-256 digests, Google's spelling

Optional:
  MODERATION_BIND                      Listen address (default: 0.0.0.0:8080)
  MODERATION_STORE_PATH                SQLite path (default: /data/moderation.sqlite)
  MODERATION_INTERFACE_COMPONENT_ID    Default: onym:component:onym-android
  MODERATION_PLAY_TOKEN_MAX_AGE_SECS   Freshness window for a token's timestampMillis
                                       (default: 600)
  MODERATION_CHALLENGE_TTL_SECS        Challenge shelf life (default: 600)
  MODERATION_PROPAGATION_GRACE_SECS    Window in which a stale read after an accepted
                                       write is treated as Google's propagation lag,
                                       not divergence (default: 60)
  MODERATION_REQUIRE_RECALL            INTERIM pre-device-recall-grant switch. Exactly
                                       "false" or "0" lets the gate answer from
                                       prerequisites 1-4 when a token carries no
                                       deviceRecall object (every other spelling stays
                                       strict — the fail-safe direction). While off,
                                       device-level ban persistence is OFF, not merely
                                       degraded. Default: true; flip back the day the
                                       grant lands ("requireRecall" on /health confirms)
  MODERATION_ENFORCE_SIGNATURES        true to reject unverifiable verdict signatures
                                       (default: false — MUST be true in production)
  MODERATION_AUTHORITY_TOKEN           Bearer token an authority presents on POST /v1/verdicts.
                                       Required: without it the endpoint refuses every request
                                       unless MODERATION_ALLOW_UNAUTHENTICATED_AUTHORITY=true
  MODERATION_AUDIT_TOKEN               Bearer token for GET /v1/write-log. Unset closes the
                                       endpoint — the log names devices, verdicts, and marks
  MODERATION_SESSION_MAX_SKEW_SECS     Freshness window for signed session timestamps
                                       (default: 300)
"#
    }
}

fn parse_secs(var: &str, default: i64) -> Result<i64, String> {
    match env::var(var) {
        Err(_) => Ok(default),
        Ok(raw) => raw
            .parse()
            .map_err(|_| format!("{var} must be an integer number of seconds")),
    }
}
