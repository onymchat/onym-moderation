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

mod api;
mod canonical;
mod cases;
mod config;
mod deadlines;
mod delivery;
mod error;
mod state;
mod store;
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
    // verdict we issue will be refused — better to say so at boot than
    // to discover it on the first ban.
    let signing_reference = util::key_reference(state.signing_key.verifying_key().as_bytes());
    if state.config.manifest.operator_key != signing_reference {
        tracing::error!(
            manifest_operator = %state.config.manifest.operator_key,
            %signing_reference,
            "manifest `operator` does not match the signing key — every verdict will be refused"
        );
    }

    if state.config.moderator_token.is_none() {
        tracing::warn!(
            "AUTHORITY_MODERATOR_TOKEN is unset — no case can be decided. Cases will still \
             resolve, by the decision-deadline default (dismissal)."
        );
    }
    if !state.delivery.configured() {
        tracing::warn!(
            "AUTHORITY_INTERFACE_URL is unset — verdicts are signed and stored but never \
             delivered, so no mark will ever move."
        );
    }

    deadlines::spawn(state.clone());

    let app = api::router(state).layer(tower_http::limit::RequestBodyLimitLayer::new(1024 * 1024));

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
