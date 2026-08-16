//! Enforcement backend for the Onym moderation seat — Google Play
//! Integrity device-recall profile.
//!
//! This service is the *interface vendor's* side of the contract, not
//! the moderation authority's. It holds the linked Cloud project's
//! service-account credentials, and therefore holds the only possible
//! write path to the per-device recall values. It decides nothing: an
//! authority signs verdicts, this executes the ones that are
//! well-formed and refuses the ones that are not.
//!
//! See ../README.md for the full boundary, and the governing spec in
//! onym-system/moderation/.

mod api;
mod canonical;
mod classifier;
mod config;
mod countersigning;
mod enforcement;
mod error;
mod google_auth;
mod payload;
mod play_integrity;
mod store;
mod types;
mod util;
mod verdict;

use std::net::SocketAddr;
use std::sync::Arc;

use api::AppState;
use config::Config;
use enforcement::{Engine, PlayEnforcement};
use google_auth::GoogleAuth;
use play_integrity::PlayIntegrity;
use store::Store;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
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

    let play = if config.play_configured() {
        let built = GoogleAuth::new(config.play_sa_key.clone().unwrap()).and_then(|auth| {
            let package = config.play_package_name.clone().unwrap();
            PlayIntegrity::new(auth, package.clone()).map(|client| PlayEnforcement {
                client,
                package_name: package,
                cert_sha256_digests: config.play_cert_sha256_digests.clone(),
                token_max_age_secs: config.play_token_max_age_secs,
            })
        });
        match built {
            Ok(play) => Some(play),
            Err(e) => {
                eprintln!("Play Integrity configuration error: {e}");
                std::process::exit(1);
            }
        }
    } else {
        // Deliberately not fatal: the service still countersigns and
        // records verdicts. But it can no longer read recall values, so
        // the gate answers `checkRequired` for everyone — degraded
        // toward blocking, never toward unmoderated operation.
        tracing::warn!(
            "Play Integrity credentials are not configured — every gate check will answer \
             checkRequired. Set MODERATION_PLAY_* to enable enforcement."
        );
        None
    };

    if !config.enforce_signatures {
        tracing::warn!(
            "MODERATION_ENFORCE_SIGNATURES is false — verdicts with unverifiable authority \
             signatures are accepted. This is for pre-launch only; set it true in production."
        );
    }

    let countersigning = countersigning::CountersigningKeys::new(
        config.interface_signing_seed,
        config.interface_key_epochs.clone(),
    );
    tracing::info!(
        interface = %config.interface_component_id,
        key = %countersigning.root_reference(),
        "interface countersigning key (authorities with no epoch configured)"
    );
    // Named individually, because an authority whose key has been
    // rotated needs the new value and there is nowhere else to read it.
    for (authority, (epoch, reference)) in countersigning.rotated() {
        tracing::info!(%authority, %epoch, key = %reference, "rotated countersigning key");
    }

    let bind_addr = config.bind_addr.clone();
    let propagation_grace_secs = config.propagation_grace_secs;
    let state = Arc::new(AppState {
        config,
        engine: Engine { store, play, propagation_grace_secs },
        countersigning,
    });

    let app = api::router(state).layer(tower_http::limit::RequestBodyLimitLayer::new(256 * 1024));

    let addr: SocketAddr = match bind_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("MODERATION_BIND {bind_addr:?} is not a socket address: {e}");
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
