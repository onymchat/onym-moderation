//! Enforcement backend for the Onym moderation seat — Apple DeviceCheck
//! profile.
//!
//! This service is the *interface vendor's* side of the contract, not
//! the moderation authority's. It holds the Apple DeviceCheck key, and
//! therefore holds the only possible write path to the two per-device
//! bits. It decides nothing: an authority signs verdicts, this executes
//! the ones that are well-formed and refuses the ones that are not.
//!
//! See ../README.md for the full boundary, and the governing spec in
//! onym-system/moderation/.

mod api;
mod canonical;
mod config;
mod countersigning;
mod devicecheck;
mod enforcement;
mod error;
mod payload;
mod store;
mod types;
mod util;
mod verdict;

use std::net::SocketAddr;
use std::sync::Arc;

use api::AppState;
use config::Config;
use devicecheck::DeviceCheck;
use enforcement::Engine;
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

    let device_check = if config.device_check_configured() {
        match DeviceCheck::new(
            config.p8_pem.as_deref().unwrap(),
            config.key_id.clone().unwrap(),
            config.team_id.clone().unwrap(),
            config.environment,
        ) {
            Ok(dc) => Some(dc),
            Err(e) => {
                eprintln!("DeviceCheck configuration error: {e}");
                std::process::exit(1);
            }
        }
    } else {
        // Deliberately not fatal: the service still countersigns and
        // records verdicts. But it can no longer read bits, so the gate
        // answers `checkRequired` for everyone — degraded toward
        // blocking, never toward unmoderated operation.
        tracing::warn!(
            "DeviceCheck credentials are not configured — every gate check will answer \
             checkRequired. Set MODERATION_DEVICECHECK_* to enable enforcement."
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
    let state = Arc::new(AppState {
        config,
        engine: Engine { store, device_check },
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
