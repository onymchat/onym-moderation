//! Shared application state.

use ed25519_dalek::SigningKey;

use crate::config::Config;
use crate::delivery::Delivery;
use crate::store::Store;
use crate::triage::Triage;

pub struct AppState {
    pub config: Config,
    pub store: Store,
    pub delivery: Delivery,
    pub signing_key: SigningKey,
    /// Present only when a classifier is configured.
    pub triage: Option<Triage>,
}

impl AppState {
    pub fn new(config: Config, store: Store) -> Self {
        let delivery = Delivery::new(
            config.interface_base_url.clone(),
            config.interface_token.clone(),
            &config.manifest_raw,
        );
        let signing_key = SigningKey::from_bytes(&config.signing_seed);
        let triage = config.triage.as_ref().map(Triage::new);
        Self { config, store, delivery, signing_key, triage }
    }

    #[cfg(test)]
    pub fn for_tests(store: Store) -> Self {
        Self::for_tests_with(store, crate::testing::MANIFEST_JSON)
    }

    #[cfg(test)]
    pub fn for_tests_with(store: Store, manifest_json: &str) -> Self {
        let manifest_raw = manifest_json.as_bytes().to_vec();
        let manifest = serde_json::from_slice(&manifest_raw).expect("test manifest");
        let config = Config {
            bind_addr: "127.0.0.1:0".into(),
            store_path: ":memory:".into(),
            manifest_raw,
            manifest,
            signing_seed: [7u8; 32],
            interface_base_url: None,
            interface_token: None,
            // Tests exercise the fail-closed path deliberately, so the
            // default fixture is a *configured* deployment; the
            // unconfigured one gets its own test.
            interface_key: Some(crate::testing::interface_key_reference()),
            moderator_token: Some("test-token".into()),
            deadline_sweep_secs: 300,
            triage: None,
            admin_token: Some("test-admin".into()),
        };
        Self::new(config, store)
    }

    /// A state wired to a classifier at `url`, running the named
    /// published profile.
    #[cfg(test)]
    pub fn for_tests_with_triage(
        store: Store,
        profile_id: &str,
        url: &str,
        mode: crate::config::TriageMode,
    ) -> Self {
        let mut state = Self::for_tests(store);
        state.config.triage = Some(crate::config::TriageConfig {
            mode,
            url: url.to_string(),
            api_key: None,
            profile: crate::profiles::by_id(profile_id).expect("published profile"),
            timeout_secs: 5,
        });
        state.triage = state.config.triage.as_ref().map(crate::triage::Triage::new);
        state
    }
}
