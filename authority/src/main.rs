//! Reference **moderation authority** for the Onym moderation seat.
//!
//! The authority's half of the contract: it receives signed reports,
//! runs cases with notice and a response window, and issues signed
//! verdicts. It never writes a device mark — it cannot, and the
//! separation is the point. The interface vendor's enforcement backend
//! (see ../apple) holds the only write path, and executes what this
//! service signs.
//!
//! Its whole authority is enumerated in the manifest it publishes, and
//! reaches only users who signed a mandate naming it.

mod admin;
mod api;
mod canonical;
mod casedoc;
mod cases;
mod config;
mod deadlines;
mod decisions;
mod delivery;
mod error;
mod policy;
mod profiles;
mod recovery;
mod state;
mod store;
mod triage;
#[cfg(test)]
mod testing;
mod types;
mod util;

use std::net::SocketAddr;
use std::sync::Arc;

use config::Config;
use state::AppState;
use store::Store;

/// Print the `onym:key:` reference of the public half of
/// `AUTHORITY_SIGNING_SEED`, and nothing else.
///
/// This exists to break a chicken-and-egg that had no other exit. The
/// manifest's `operator` must name the key this service signs with, and
/// boot refuses when the two disagree — correctly, since a verdict
/// signed by a key the manifest does not name is unverifiable. But the
/// public half is derived from a seed that lives in a secret store, so
/// there was no way to learn it without first standing the service up
/// against a manifest that could not yet be right.
///
/// Deriving it here keeps the seed where it belongs. The operator runs
/// this locally, against their own secret, and the only thing that
/// leaves is a public key.
fn derive_operator_key() -> ! {
    let seed = seed_from_env();
    // Bare on stdout, so it can be piped straight into the manifest.
    println!("{}", operator_key_for(&seed));
    std::process::exit(0);
}

/// The manifest's `operator` value for a signing seed.
///
/// Shared with the boot check rather than reimplemented beside it: a
/// derivation that disagreed with the one the service compares against
/// would hand operators a key guaranteed to fail the check it exists to
/// satisfy.
fn operator_key_for(seed: &[u8; 32]) -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(seed);
    util::key_reference(key.verifying_key().as_bytes())
}

/// Sign a file's exact bytes with `AUTHORITY_SIGNING_SEED` and print
/// the detached Ed25519 signature as base64, and nothing else.
///
/// This exists so a deployment can publish `manifest.json.sig` next to
/// the manifest it materialized: clients verify the manifest's exact
/// bytes against the directory-pinned operator key before trusting the
/// terms inside, and without the detached signature they can only
/// accept it soft-verified. Like `derive-operator-key`, the seed never
/// leaves its secret store — the operator runs this against their own
/// secret and the only thing that comes out is a signature over bytes
/// that were already public.
///
/// Signing is deliberately over the file's raw bytes, not a parsed or
/// re-encoded form: mandates pin the manifest's exact bytes, and the
/// signature must cover the same artifact.
fn sign_manifest(path: &str) -> ! {
    use ed25519_dalek::Signer;

    let seed = seed_from_env();
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("could not read {path}: {e}");
            std::process::exit(1);
        }
    };
    if bytes.is_empty() {
        eprintln!("{path} is empty; refusing to sign an empty manifest.");
        std::process::exit(1);
    }
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let signature = key.sign(&bytes);
    // Bare on stdout, so it can be piped straight into the `.sig` file.
    println!("{}", util::base64_encode(&signature.to_bytes()));
    std::process::exit(0);
}

/// `AUTHORITY_SIGNING_SEED` as raw bytes, or a usage error. Shared by
/// both operator subcommands so their seed handling cannot drift.
fn seed_from_env() -> [u8; 32] {
    let Ok(hex_seed) = std::env::var("AUTHORITY_SIGNING_SEED") else {
        eprintln!(
            "AUTHORITY_SIGNING_SEED is not set.\n\n\
             Generate one with `openssl rand -hex 32` and keep it in a secret store. It signs \
             every verdict this authority issues, so rotating it later invalidates all of them \
             — treat it as long-lived from the start."
        );
        std::process::exit(1);
    };
    match hex::decode(hex_seed.trim()).ok().and_then(|raw| raw.try_into().ok()) {
        Some(seed) => seed,
        None => {
            eprintln!("AUTHORITY_SIGNING_SEED must be 32 bytes as 64 hex characters.");
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() {
    // Before anything reads a manifest or opens a store: this
    // subcommand is what an operator runs *because* those are not
    // configured yet.
    if std::env::args().nth(1).as_deref() == Some("derive-operator-key") {
        derive_operator_key();
    }
    if std::env::args().nth(1).as_deref() == Some("sign-manifest") {
        let Some(path) = std::env::args().nth(2) else {
            eprintln!("usage: onym-moderation-authority sign-manifest <manifest-path>");
            std::process::exit(1);
        };
        sign_manifest(&path);
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {e}\n");
            eprintln!("{}", Config::usage());
            std::process::exit(1);
        }
    };

    let store = match Store::open(&config.store_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let bind_addr = config.bind_addr.clone();
    let state = Arc::new(AppState::new(config, store));

    let manifest_hash = util::sha256_hex(&state.config.manifest_raw);
    tracing::info!(
        authority = %state.config.manifest.component_id,
        signing_key = %util::key_reference(state.signing_key.verifying_key().as_bytes()),
        %manifest_hash,
        "authority starting"
    );

    // The manifest names an operator key; verdicts are checked against
    // it downstream. If it doesn't match the key we sign with, every
    // verdict this authority issues is unverifiable — so refuse to
    // start rather than run a service whose output nobody can check. A
    // warning was not enough: it produces an authority that looks
    // healthy, decides cases, and moves no marks.
    let signing_reference = util::key_reference(state.signing_key.verifying_key().as_bytes());
    if state.config.manifest.operator_key != signing_reference {
        eprintln!(
            "Configuration error: the manifest's `operator` is {} but this service signs with \
             {}.\n\nEvery verdict issued would be refused downstream. Put this key in the \
             manifest's `operator` field:\n\n    {}\n\n…or point AUTHORITY_SIGNING_SEED at the \
             key the manifest already names. To derive the key from a seed without starting the \
             service:\n\n    AUTHORITY_SIGNING_SEED=… onym-moderation-authority \
             derive-operator-key\n",
            state.config.manifest.operator_key, signing_reference, signing_reference
        );
        std::process::exit(1);
    }

    // An expired manifest may not take new mandates or open new cases
    // (§5.2 constraint 5). Live process continues, so this is a refusal
    // at intake rather than at startup — but say it loudly at boot,
    // because the symptom otherwise is "reports mysteriously refused".
    match util::parse_timestamp(&state.config.manifest.valid_until) {
        Ok(valid_until) if valid_until <= time::OffsetDateTime::now_utc() => {
            tracing::error!(
                valid_until = %state.config.manifest.valid_until,
                "manifest validUntil has passed: no new mandate or case will be accepted. \
                 Cases already open still run to their deadlines."
            );
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!("Configuration error: manifest validUntil is unparseable: {e}");
            std::process::exit(1);
        }
    }

    // Who, if anyone, can actually decide a case.
    //
    // Autonomous triage decides without either token; the JSON API
    // needs `AUTHORITY_MODERATOR_TOKEN` and the panel needs
    // `AUTHORITY_ADMIN_TOKEN`. With no classifier and neither token,
    // this service accepts reports, opens cases, serves notice, runs
    // every response window — and then dismisses all of them by
    // default, because nothing on earth can reach a verdict. That is an
    // authority which looks healthy and is not one, which is the same
    // failure the operator-key check above refuses to start over, so
    // this refuses too.
    let autonomous = matches!(
        state.config.triage.as_ref().map(|t| t.mode),
        Some(config::TriageMode::Autonomous)
    );
    let human_can_decide =
        state.config.moderator_token.is_some() || state.config.admin_token.is_some();
    if !autonomous && !human_can_decide {
        eprintln!(
            "Configuration error: nothing can decide a case.\n\n\
             AUTHORITY_TRIAGE_MODE is not autonomous, so a person has to decide — but \
             AUTHORITY_MODERATOR_TOKEN (the JSON API) and AUTHORITY_ADMIN_TOKEN (the panel at \
             /admin) are both unset, and those are the only two ways in.\n\n\
             Left running, this authority would accept reports, open cases, serve notice, run \
             every response window, and dismiss all of them at their decision deadlines. Set one \
             of the two tokens, or set AUTHORITY_TRIAGE_MODE=autonomous with a model profile in \
             the manifest."
        );
        std::process::exit(1);
    }
    if !autonomous && state.config.admin_token.is_none() {
        tracing::warn!(
            "AUTHORITY_ADMIN_TOKEN is unset, so the panel at /admin is closed. With no \
             classifier running, every case must be decided through the JSON API instead — and \
             appeals have no other route at all."
        );
    }
    if state.config.moderator_token.is_none() {
        tracing::warn!(
            "AUTHORITY_MODERATOR_TOKEN is unset — POST /v1/cases/:id/decide is closed."
        );
    }
    // Triage reads the evidence in a case. Where that inference runs
    // decides whether recipient-disclosed content stays with the
    // operator the user consented to, so it is checked at boot rather
    // than left to whoever wrote the compose file.
    if let Some(triage) = state.config.triage.as_ref() {
        tracing::info!(
            mode = ?triage.mode,
            url = %triage.url,
            profile = %triage.profile.id,
            repository = %triage.profile.repository,
            revision = %triage.profile.revision,
            served_model = %triage.profile.served_model,
            profile_digest = %triage.profile.profile_digest,
            policy_digest = %triage.profile.policy_digest,
            native_taxonomy = triage.profile.native_taxonomy,
            "triage enabled"
        );

        // The published manifest is what users consent to. If it names
        // a model profile, running a different one means deciding
        // cases under terms nobody agreed to — so refuse to start
        // rather than discover it in a case record.
        match state.config.manifest.model_profile.as_ref() {
            Some(declared)
                if declared.id != triage.profile.id
                    || declared.digest != triage.profile.profile_digest =>
            {
                eprintln!(
                    "Configuration error: the manifest declares model profile {} ({}), but \
                     AUTHORITY_TRIAGE_PROFILE selects {} ({}).\n\nWhich model decides a case is \
                     consented policy and may not be replaced by a deployment. Run the profile \
                     the manifest names, or publish a new manifest and take fresh mandates \
                     against it.",
                    declared.id,
                    declared.digest,
                    triage.profile.id,
                    triage.profile.profile_digest
                );
                std::process::exit(1);
            }
            Some(_) => {}
            None if triage.mode == crate::config::TriageMode::Autonomous => {
                // Autonomous means this profile decides cases with no
                // human in the loop. With nothing in the manifest
                // naming it, the terms users consented to say nothing
                // about which model that is — so there is no answer to
                // "was I judged under what I agreed to?", and the honest
                // response is to refuse rather than to warn and decide
                // anyway.
                eprintln!(
                    "Configuration error: AUTHORITY_TRIAGE_MODE is autonomous but the published \
                     manifest declares no `modelProfile`.\n\nNothing then binds the classifier \
                     that decides cases to the terms users consented to. Declare it — the \
                     profile's id and the SHA-256 of its published document — or run in \
                     advisory mode, where a human decides."
                );
                std::process::exit(1);
            }
            None => tracing::warn!(
                profile = %triage.profile.id,
                "the published manifest declares no `modelProfile`, so nothing binds this \
                 deployment's classifier to the terms users consented to. Add one — id and the \
                 SHA-256 of the published profile document — and cases become checkable."
            ),
        }

        // A native taxonomy decides by the model's own categories, and
        // the published profiles say plainly that those categories do
        // not establish the elements of the narrower rule — Qwen's
        // `Sexual Content or Sexual Acts` does not establish that
        // anyone is under 18. That mismatch is meant to be caught by a
        // human on appeal. Wire it to a class whose ban is permanent,
        // in autonomous mode, and the first human to look at the case
        // is looking at a permanent ban that was issued on a category
        // admittedly unable to prove the offence.
        if triage.profile.native_taxonomy && triage.mode == crate::config::TriageMode::Autonomous {
            let permanent: Vec<&str> = state
                .config
                .manifest
                .violation_classes
                .iter()
                .filter(|class| class.ban_term == "permanent")
                .map(|class| class.class_id.as_str())
                .collect();
            if !permanent.is_empty() {
                tracing::error!(
                    profile = %triage.profile.id,
                    classes = %permanent.join(", "),
                    "this profile decides by the model's own categories, which its published \
                     terms say do not establish the narrower rule's elements — and these classes \
                     carry a permanent ban with no human before the verdict. Prefer a profile \
                     that applies the canonical rule for permanent-term classes, or run in \
                     advisory mode."
                );
            }
        }

        // A class the profile cannot decide is not fatal — those cases
        // wait for a human and dismiss at their deadline — but the
        // symptom is "the classifier has gone quiet", which is a bad
        // thing to have to diagnose from case records.
        let unmappable = crate::triage::unmappable_classes(&triage.profile, &state.config.manifest);
        if !unmappable.is_empty() {
            tracing::warn!(
                classes = %unmappable.join(", "),
                profile = %triage.profile.id,
                "this profile has no rule or native category for these manifest classes; cases \
                 in them will never be decided automatically"
            );
        }
        if crate::triage::needs_logprobs(&triage.profile) {
            tracing::info!(
                "this profile scores from first-token log probabilities; the inference server \
                 must support `logprobs` and `top_logprobs` or every case will reach no decision"
            );
        }
        if Config::triage_leaves_this_host(triage) {
            // Fatal, not logged. Everything else consent-critical here
            // refuses to start — no default profile, no mode without a
            // profile — and this is the one that puts recipient-
            // disclosed evidence in front of a third party. A log line
            // is exactly what an operator misses, and by the time they
            // read it the disclosure has already happened.
            eprintln!(
                "Configuration error: AUTHORITY_TRIAGE_URL is {}, which is not on this host.\n\n\
                 Case evidence is content a reporter disclosed for adjudication. Sending it to \
                 a third party is a further disclosure — one the manifest's confidentiality \
                 policy must declare (§8 obligation 6), and one the reference policy makes a \
                 change requiring fresh consent.\n\n\
                 Run the model on this host, or set AUTHORITY_TRIAGE_MODE=off.",
                triage.url
            );
            std::process::exit(1);
        }
        if state.config.manifest.confidentiality.is_none() {
            tracing::warn!(
                "triage is enabled but the manifest declares no confidentiality policy; users \
                 consented without being told their disclosed evidence is machine-classified"
            );
        }
        // Autonomous means nobody reads the file before a mark moves.
        // The contract permits it; a user is owed the disclosure.
        if triage.mode == crate::config::TriageMode::Autonomous {
            tracing::warn!(
                "triage mode is autonomous: verdicts issue without human review, and a human \
                 sees a case only if it is appealed"
            );
        }
    }

    if state.config.admin_token.is_none() {
        tracing::warn!(
            "AUTHORITY_ADMIN_TOKEN is unset — the moderator panel is closed, so appeals cannot \
             be reviewed by a human at all"
        );
    }

    if !state.delivery.configured() {
        tracing::warn!(
            "AUTHORITY_INTERFACE_URL is unset — verdicts are signed and stored but never \
             delivered, so no mark will ever move."
        );
    }

    deadlines::spawn(state.clone());

    let app = api::router(state.clone())
        .merge(admin::router(state))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(1024 * 1024));

    let addr: SocketAddr = match bind_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("AUTHORITY_BIND {bind_addr:?} is not a socket address: {e}");
            std::process::exit(1);
        }
    };
    tracing::info!(%addr, "listening");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The subcommand and the boot check must agree. If they did not,
    /// `derive-operator-key` would hand an operator the one value
    /// guaranteed to fail the check it exists to satisfy — and the
    /// symptom would be a service that refuses to start while the
    /// manifest looks correct.
    #[test]
    fn the_derived_key_is_the_one_boot_compares_against() {
        let state = AppState::for_tests(Store::in_memory().unwrap());
        let seed = state.config.signing_seed;
        let at_boot = util::key_reference(state.signing_key.verifying_key().as_bytes());
        assert_eq!(operator_key_for(&seed), at_boot);
        assert!(at_boot.starts_with("onym:key:"));
        assert_eq!(at_boot.len(), "onym:key:".len() + 64);
    }
}
