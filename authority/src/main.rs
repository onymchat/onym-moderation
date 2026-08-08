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

#[tokio::main]
async fn main() {
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
             {}.\n\nEvery verdict issued would be refused downstream. Put the signing key in the \
             manifest's `operator` field, or point AUTHORITY_SIGNING_SEED at the key the manifest \
             already names.",
            state.config.manifest.operator_key, signing_reference
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

    if state.config.moderator_token.is_none() {
        tracing::warn!(
            "AUTHORITY_MODERATOR_TOKEN is unset — no case can be decided. Cases will still \
             resolve, by the decision-deadline default (dismissal)."
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
