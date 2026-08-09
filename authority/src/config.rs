//! Environment-driven configuration.

use std::env;

use crate::profiles::{self, ModelProfile};
use crate::types::AuthorityManifest;

/// The SHA-256 a supplied profile document is named by: its bytes with
/// `profileDigest` dropped structurally and the rest re-serialized with
/// sorted keys — the same canonicalization every signature in this
/// service uses.
///
/// Dropping the field is what makes the digest constructible: a
/// document cannot state a hash of itself that includes the statement.
/// Dropping it *structurally* rather than by string surgery is what
/// keeps it honest — removing every occurrence of a digest-shaped
/// string would let a planted copy elsewhere in the document
/// reconstruct different bytes than the ones that decide cases.
///
/// Equivalent to `jq -cSj 'del(.profileDigest)' profile.json |
/// shasum -a 256`, which is what the README tells operators to run.
pub fn profile_digest(raw: &[u8]) -> Result<String, String> {
    let bytes = crate::canonical::canonical_bytes(raw, &["profileDigest"])
        .map_err(|e| format!("cannot canonicalize the profile document: {e}"))?;
    Ok(crate::util::sha256_hex(&bytes))
}

/// What to make of a triage host that cannot be resolved right now.
/// The two callers want different answers, and the difference is the
/// whole of the boot-time leniency.
#[derive(Clone, Copy)]
pub enum Unresolved {
    /// Boot: the sibling container may not be up yet.
    TreatAsLocal,
    /// First use: nothing says it is here, and evidence is about to
    /// leave the process.
    TreatAsRemote,
}

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
    /// The interface's countersigning key(s), used to check that a
    /// registered mandate really was countersigned by the interface
    /// that claims to have witnessed it.
    ///
    /// A list, because the interface derives a separate key per
    /// authority and can rotate ours. With one accepted key there is no
    /// order in which a rotation avoids downtime: whichever side moves
    /// first, registrations fail until the other catches up. Accepting
    /// the incoming key alongside the outgoing one closes that window —
    /// add the new, let the interface cut over, then drop the old.
    ///
    /// Empty means unconfigured, which refuses every registration.
    pub interface_keys: Vec<String>,

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

    /// Development-only escape hatch for exercising the ban UI without
    /// waiting for a production-length response window. Off by default;
    /// this must never be enabled on a public authority.
    pub allow_early_ban_for_qa: bool,
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
                let mut profile = serde_json::from_slice::<ModelProfile>(&raw)
                    .map_err(|e| format!("{path} is not a valid model profile: {e}"))?;

                // The digest is computed over the document actually
                // loaded, not read out of it. Trusting the file's own
                // `profileDigest` made the binding a self-assertion: a
                // prompt, adapter, threshold or revision could be
                // rewritten while the field stayed put, and boot would
                // then match that unchanged string against the
                // manifest and judge an old mandate under replacement
                // terms.
                //
                // But it must be a digest an operator can actually
                // produce. Hashing the whole file including its own
                // `profileDigest` is self-referential — writing the
                // value in changes the bytes it was computed from — so
                // the documented procedure could never yield a
                // document that passed, and the only way through was
                // to leave the field empty, which skipped the check
                // entirely. So: the digest names the profile's
                // *execution bytes* — every field except the digest,
                // re-serialized with sorted keys. Those are the bytes
                // that decide cases, which is what a mandate consents
                // to; and inserting the result does not disturb them.
                let computed = profile_digest(&raw)
                    .map_err(|e| format!("AUTHORITY_TRIAGE_PROFILE_PATH {path}: {e}"))?;
                if !profile.profile_digest.is_empty() && profile.profile_digest != computed {
                    return Err(format!(
                        "{path} declares profileDigest {} but its execution bytes hash to \
                         {computed}. The digest names the document a mandate consents to; it \
                         cannot be asserted separately from the document it names. Compute it \
                         with: jq -cSj 'del(.profileDigest)' {path} | shasum -a 256",
                        profile.profile_digest
                    ));
                }
                profile.profile_digest = computed;

                // Thresholds are consented policy, and a profile whose
                // band is inverted or collapsed has no state in which
                // it declines to decide — the band is the model's way
                // of saying "ask a person", and without it every
                // reading becomes a verdict. Published profiles are
                // checked by construction; a supplied one is checked
                // here.
                if let crate::profiles::Adapter::FirstTokenScore {
                    ban_at, dismiss_at, ..
                } = profile.adapter
                {
                    if !(0.0..=1.0).contains(&ban_at) || !(0.0..=1.0).contains(&dismiss_at) {
                        return Err(format!(
                            "{path}: banAt and dismissAt must each be between 0 and 1 (got \
                             {ban_at} and {dismiss_at})"
                        ));
                    }
                    if dismiss_at >= ban_at {
                        return Err(format!(
                            "{path}: dismissAt {dismiss_at} is not below banAt {ban_at}, so there \
                             is no band in which this profile declines to decide. That band is \
                             what sends a case to a human instead of to a verdict."
                        ));
                    }
                }
                profile
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
            // Comma-separated so a rotation can list both keys at
            // once. Order is irrelevant; each is tried.
            interface_keys: env::var("AUTHORITY_INTERFACE_KEY")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|key| !key.is_empty())
                .map(str::to_string)
                .collect(),
            moderator_token: env::var("AUTHORITY_MODERATOR_TOKEN").ok().filter(|v| !v.is_empty()),
            deadline_sweep_secs: env::var("AUTHORITY_DEADLINE_SWEEP_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
            triage: TriageConfig::from_env()?,
            admin_token: env::var("AUTHORITY_ADMIN_TOKEN").ok().filter(|v| !v.is_empty()),
            allow_early_ban_for_qa: env::var("AUTHORITY_QA_ALLOW_EARLY_BAN")
                .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
                .unwrap_or(false),
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
    /// At boot, a name that cannot be resolved *yet* is accepted: the
    /// model container may have started second, and refusing to start
    /// over that is its own failure. The check is deferred, not
    /// skipped — `Triage::infer` pays it before the first request that
    /// would carry evidence.
    pub fn triage_leaves_this_host(triage: &TriageConfig) -> bool {
        !Self::is_local_host(Self::host_of(&triage.url), Unresolved::TreatAsLocal)
    }

    /// The same question with the boot leniency removed: the host must
    /// actually resolve, and resolve here. This is what the deferred
    /// check asks, and what the documentation describes.
    pub fn triage_host_resolves_local(triage: &TriageConfig) -> bool {
        Self::is_local_host(Self::host_of(&triage.url), Unresolved::TreatAsRemote)
    }

    /// The host part of a URL, with a bracketed IPv6 literal unwrapped.
    ///
    /// Splitting on `:` to drop the port cannot come first: `[::1]:8000`
    /// would become `[`, and every IPv6 arm below would be dead code
    /// that only looked like it was doing something.
    fn host_of(url: &str) -> &str {
        let authority = url
            .split("://")
            .nth(1)
            .unwrap_or(url)
            .split('/')
            .next()
            .unwrap_or("");
        match authority.strip_prefix('[') {
            // `[::1]:8000` → `::1`
            Some(rest) => rest.split(']').next().unwrap_or(""),
            None => authority.split(':').next().unwrap_or(""),
        }
    }

    /// Whether a host is this machine or the private network it shares
    /// with a sibling container.
    ///
    /// The private ranges are parsed rather than prefix-matched.
    /// `starts_with("172.2")` accepted `172.20.0.5`, which is private,
    /// and `172.2.3.4`, which is a routable address on the public
    /// internet — and this check is the one thing standing between
    /// "the model runs here" and shipping disclosed evidence to a
    /// stranger.
    fn is_local_host(host: &str, unresolved: Unresolved) -> bool {
        let unresolved = matches!(unresolved, Unresolved::TreatAsLocal);
        if host.is_empty() {
            return false;
        }
        if host == "localhost" || host == "::1" {
            return true;
        }
        // `.localhost` is conventionally loopback but is still a DNS
        // name: `evil.localhost` can be made to resolve anywhere.
        // Trusting the suffix skipped the very check the dotless case
        // gets, so it goes through the same resolution.
        if host.ends_with(".localhost") {
            return match Self::resolve(host) {
                Some(addresses) => addresses.iter().all(Self::is_local_ip),
                None => unresolved,
            };
        }
        // A bare name with no dots is *usually* a compose service on
        // the private network — but "usually" is not good enough for
        // the check that decides whether disclosed evidence leaves the
        // host. A DNS search domain can resolve `evil` to anywhere, so
        // the name is resolved and its addresses are checked. If it
        // cannot be resolved yet (the sibling container may not be up),
        // a dotless name is accepted: refusing to boot because the
        // model container started second would be its own failure.
        if !host.contains('.') && !host.contains(':') {
            return match Self::resolve(host) {
                Some(addresses) => addresses.iter().all(Self::is_local_ip),
                None => unresolved,
            };
        }
        // A dotted *literal* is judged by its octets.
        if let Some(octets) = Self::ipv4_octets(host) {
            return match octets {
                [127, _, _, _] => true,
                [10, _, _, _] => true,
                [192, 168, _, _] => true,
                [172, second, _, _] => (16..=31).contains(&second),
                _ => false,
            };
        }

        // A dotted *name* is resolved, like a dotless one. Rejecting
        // every dotted non-literal made `host.docker.internal` and
        // `model.svc.cluster.local` hard boot failures even when they
        // resolve to loopback — and a check that refuses correct
        // deployments is a check operators route around, which costs
        // more than it protects.
        match Self::resolve(host) {
            Some(addresses) => addresses.iter().all(Self::is_local_ip),
            // Unresolvable and dotted: nothing says it is on this host.
            None => false,
        }
    }

    /// Resolve a host to its addresses. `None` when it cannot be
    /// resolved at all, which is a different answer from "resolves off
    /// this host".
    fn resolve(host: &str) -> Option<Vec<std::net::IpAddr>> {
        use std::net::ToSocketAddrs;
        let resolved: Vec<std::net::IpAddr> =
            (host, 0u16).to_socket_addrs().ok()?.map(|address| address.ip()).collect();
        (!resolved.is_empty()).then_some(resolved)
    }

    fn is_local_ip(address: &std::net::IpAddr) -> bool {
        match address {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local()
            }
            std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.segments()[0] & 0xfe00 == 0xfc00,
        }
    }

    fn ipv4_octets(host: &str) -> Option<[u8; 4]> {
        let mut parts = host.split('.');
        let mut octets = [0u8; 4];
        for octet in octets.iter_mut() {
            *octet = parts.next()?.parse().ok()?;
        }
        parts.next().is_none().then_some(octets)
    }

    pub fn usage() -> &'static str {
        r#"Required:
  AUTHORITY_MANIFEST_PATH      Path to this authority's published manifest.json.
                               Served verbatim; the bytes are what users' mandates pin.
  AUTHORITY_SIGNING_SEED       32-byte hex seed for the verdict-signing key
                               (generate: openssl rand -hex 32). Keep it separate from
                               operational secrets, and never rotate it while bans run —
                               verdicts already issued would stop verifying.
                               The manifest's `operator` must name this key's public
                               half. To print it without starting the service:
                                 AUTHORITY_SIGNING_SEED=… onym-moderation-authority \
                                     derive-operator-key

Delivering verdicts to the interface:
  AUTHORITY_INTERFACE_URL      Base URL of the enforcement backend (e.g.
                               https://moderation.onym.app)
  AUTHORITY_INTERFACE_TOKEN    Its MODERATION_AUTHORITY_TOKEN
  AUTHORITY_INTERFACE_KEY      onym:key:<hex> of the interface's countersigning key for
                               this authority, used to check registered mandates were
                               really countersigned. From the interface's /health:
                               rotatedInterfaceKeys["<our componentId>"].key if present,
                               else interfaceKey — it derives a key per authority, so the
                               root is only ours until someone rotates us.
                               Comma-separate two to ride out a rotation with no gap.

Optional:
  AUTHORITY_BIND               Listen address (default: 0.0.0.0:8080)
  AUTHORITY_STORE_PATH         SQLite path (default: /data/authority.sqlite)
  AUTHORITY_MODERATOR_TOKEN    Bearer token for POST /v1/cases/:id/decide.
                               Unset closes the endpoint — nothing may decide a case.
  AUTHORITY_DEADLINE_SWEEP_SECS  How often to dismiss overdue cases, and assess cases
                               whose response window has closed (default: 300)
  AUTHORITY_ADMIN_TOKEN        Bearer token for the moderator panel at /admin, where
                               appeals are reviewed. Unset closes it.
  AUTHORITY_APPEAL_EMAIL       Public email address for manual appeals when a user
                               cannot recover the original device identity. Returned
                               by /health; omit it to expose no email.

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

#[cfg(test)]
mod tests {
    use super::*;

    /// `TriageConfig::from_env` reads process-wide state, and the test
    /// runner is threaded. Two tests setting `AUTHORITY_TRIAGE_*` at
    /// once read each other's variables — one of them sees the other's
    /// teardown and gets `Ok(None)`. Every test that touches those
    /// variables takes this first.
    static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// `starts_with("172.2")` matched `172.20.0.5`, which is private,
    /// and `172.2.3.4`, which is a routable address on the public
    /// internet. This check is the one thing standing between "the
    /// model runs here" and shipping disclosed evidence to a stranger,
    /// so the octets are parsed.
    #[test]
    fn private_ranges_are_parsed_not_prefix_matched() {
        for local in [
            "http://localhost:8000/v1/chat/completions",
            "http://127.0.0.1:8000/v1",
            "http://10.1.2.3:8000/v1",
            "http://192.168.1.10:8000/v1",
            "http://172.16.0.1:8000/v1",
            "http://172.20.0.5:8000/v1",
            "http://172.31.255.254:8000/v1",
            "http://moderation-model:8000/v1",
        ] {
            assert!(Config::is_local_host(Config::host_of(local), Unresolved::TreatAsLocal), "{local}");
        }

        for remote in [
            // The one the prefix match got wrong: routable, not private.
            "http://172.2.3.4:8000/v1",
            "http://172.15.0.1:8000/v1",
            "http://172.32.0.1:8000/v1",
            "http://api.example.com/v1/chat/completions",
            "https://10.example.com/v1",
            "http://192.168.1.10.example.com/v1",
        ] {
            assert!(!Config::is_local_host(Config::host_of(remote), Unresolved::TreatAsLocal), "{remote}");
        }
    }

    /// Dropping the port by splitting on `:` cannot come first — an
    /// IPv6 literal is full of colons, and `[::1]:8000` became `[`.
    #[test]
    fn bracketed_ipv6_literals_survive_port_stripping() {
        assert_eq!(Config::host_of("http://[::1]:8000/v1/chat/completions"), "::1");
        assert!(Config::is_local_host(Config::host_of("http://[::1]:8000/v1"), Unresolved::TreatAsLocal));
        assert_eq!(Config::host_of("http://[2001:db8::1]:8000/v1"), "2001:db8::1");
        assert!(
            !Config::is_local_host(Config::host_of("http://[2001:db8::1]:8000/v1"), Unresolved::TreatAsLocal),
            "a routable IPv6 address is not this host"
        );
    }

    /// A dotted name that resolves to a private address is on this
    /// host. Rejecting every dotted non-literal made
    /// `host.docker.internal` a hard boot failure, and a check that
    /// refuses correct deployments is one operators route around.
    #[test]
    fn a_dotted_name_is_judged_by_what_it_resolves_to() {
        // `localhost.` and similar resolve to loopback on any sane
        // resolver; if this environment cannot resolve it, the
        // assertion below is skipped rather than made flaky.
        if let Some(addresses) = Config::resolve("localhost") {
            assert!(addresses.iter().all(Config::is_local_ip));
        }
        // A dotted literal is still judged by its octets, with no
        // lookup at all.
        assert!(Config::is_local_host("10.0.0.1", Unresolved::TreatAsLocal));
        assert!(!Config::is_local_host("172.2.3.4", Unresolved::TreatAsLocal));
        // And a name that resolves nowhere is not assumed local.
        assert!(!Config::is_local_host("no-such-host.invalid", Unresolved::TreatAsLocal));
    }

    /// A profile whose band is inverted or collapsed has no state in
    /// which it declines to decide, and that band is what sends a case
    /// to a person instead of to a verdict.
    #[test]
    fn a_custom_profile_needs_a_band_to_decline_in() {
        let _guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir();
        let path = dir.join(format!("onym-profile-{}.json", std::process::id()));
        let body = |ban: f64, dismiss: f64| {
            format!(
                r#"{{"id":"house","displayName":"House","profileDigest":"","policyDigest":"p",
                    "repository":"o/r","revision":"r","servedModel":"m","supportsImages":false,
                    "maxInputTokens":8192,"nativeTaxonomy":false,
                    "prompt":{{"user":"{{document}}","usesCanonicalRule":true}},
                    "adapter":{{"kind":"firstTokenScore","positive":["yes"],"negative":["no"],
                                "banAt":{ban},"dismissAt":{dismiss}}}}}"#
            )
        };

        std::fs::write(&path, body(0.2, 0.9)).unwrap();
        std::env::set_var("AUTHORITY_TRIAGE_MODE", "advisory");
        std::env::set_var("AUTHORITY_TRIAGE_PROFILE_PATH", path.to_str().unwrap());
        std::env::remove_var("AUTHORITY_TRIAGE_PROFILE");
        let inverted = TriageConfig::from_env();
        assert!(inverted.is_err(), "an inverted band must be refused: {inverted:?}");

        std::fs::write(&path, body(0.9, 0.2)).unwrap();
        let valid = TriageConfig::from_env();
        assert!(valid.is_ok(), "and a real one accepted: {:?}", valid.err());

        std::env::remove_var("AUTHORITY_TRIAGE_MODE");
        std::env::remove_var("AUTHORITY_TRIAGE_PROFILE_PATH");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_host_is_taken_from_the_url_not_the_path() {
        assert_eq!(Config::host_of("http://example.com:8000/localhost"), "example.com");
        assert_eq!(Config::host_of("http://example.com/v1"), "example.com");
    }

    /// The digest a mandate consents to has to be one an operator can
    /// actually produce. Hashing the whole file including its own
    /// `profileDigest` was self-referential — writing the value in
    /// changed the bytes it was computed from — so the documented
    /// procedure could never yield a document that loaded, and the
    /// only way through was to leave the field empty, which skipped
    /// the check entirely.
    #[test]
    fn a_declared_profile_digest_can_be_constructed_and_is_checked() {
        let _guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let document = |digest: &str| {
            format!(
                r#"{{"id":"house","displayName":"House","profileDigest":"{digest}",
                    "policyDigest":"p","repository":"o/r","revision":"r","servedModel":"m",
                    "supportsImages":false,"maxInputTokens":8192,"nativeTaxonomy":false,
                    "prompt":{{"user":"{{document}}","usesCanonicalRule":true}},
                    "adapter":{{"kind":"exactOutput","ban":"VIOLATION","dismiss":"CLEAR"}}}}"#
            )
        };

        // Compute it the way the README says, then write it in.
        let computed = profile_digest(document("").as_bytes()).unwrap();
        // The README tells operators to run
        //   jq -cSj 'del(.profileDigest)' profile.json | shasum -a 256
        // against exactly this document. If the canonicalization here
        // ever stops agreeing with that command, the instruction sends
        // people to a value the service will reject.
        assert_eq!(
            computed, "cc15509fbc75bed206acb399efaae5e16f755870fef54718272711171fdd96e1",
            "the documented jq command no longer reproduces this digest"
        );
        let declared = document(&computed);
        assert_eq!(
            profile_digest(declared.as_bytes()).unwrap(),
            computed,
            "inserting the digest must not change the bytes it names"
        );

        let dir = std::env::temp_dir();
        let path = dir.join(format!("onym-digest-{}.json", std::process::id()));
        std::fs::write(&path, &declared).unwrap();
        std::env::set_var("AUTHORITY_TRIAGE_MODE", "advisory");
        std::env::set_var("AUTHORITY_TRIAGE_PROFILE_PATH", path.to_str().unwrap());
        std::env::remove_var("AUTHORITY_TRIAGE_PROFILE");

        let loaded = TriageConfig::from_env().expect("a correctly declared digest must load");
        assert_eq!(loaded.unwrap().profile.profile_digest, computed);

        // And it is still a check, not a formality: a document whose
        // execution bytes were edited after the digest was written no
        // longer matches.
        let tampered = declared.replace("\"CLEAR\"", "\"NOT A VIOLATION\"");
        std::fs::write(&path, &tampered).unwrap();
        let rejected = TriageConfig::from_env();
        assert!(rejected.is_err(), "a rewritten profile must not load: {rejected:?}");

        std::env::remove_var("AUTHORITY_TRIAGE_MODE");
        std::env::remove_var("AUTHORITY_TRIAGE_PROFILE_PATH");
        let _ = std::fs::remove_file(&path);
    }

    /// A name that does not resolve is accepted at boot — the model
    /// container may have started second — and refused at first use.
    /// The documentation states the off-host check unconditionally, so
    /// the leniency has to be a deferral rather than a hole a typo'd
    /// or not-yet-published name falls through.
    #[test]
    fn an_unresolvable_host_is_a_deferred_check_not_a_skipped_one() {
        let triage = |url: &str| TriageConfig {
            mode: TriageMode::Advisory,
            url: url.to_string(),
            api_key: None,
            profile: profiles::by_id("qwen3guard-8b").unwrap(),
            timeout_secs: 5,
        };

        // Boot lets it through…
        let unresolvable = triage("http://not-a-real-sibling/v1/chat/completions");
        assert!(!Config::triage_leaves_this_host(&unresolvable));
        // …and the check that runs before evidence leaves does not.
        assert!(!Config::triage_host_resolves_local(&unresolvable));

        // A `.localhost` name is decided by resolution, not by its
        // suffix — conventionally loopback is not the same as *being*
        // loopback. Which way it goes depends on the resolver, so the
        // assertion is that the two checks agree with the lookup rather
        // than with the spelling.
        let dotted = triage("http://nothing-here.localhost:8000/v1/chat/completions");
        let resolves_local = Config::resolve("nothing-here.localhost")
            .is_some_and(|addresses| addresses.iter().all(Config::is_local_ip));
        assert_eq!(Config::triage_host_resolves_local(&dotted), resolves_local);

        // A literal needs no lookup and passes both.
        let literal = triage("http://127.0.0.1:8000/v1/chat/completions");
        assert!(!Config::triage_leaves_this_host(&literal));
        assert!(Config::triage_host_resolves_local(&literal));

        // And a public address fails both.
        let remote = triage("https://api.example.com/v1/chat/completions");
        assert!(Config::triage_leaves_this_host(&remote));
        assert!(!Config::triage_host_resolves_local(&remote));
    }
}
