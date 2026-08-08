//! Shared application state.

use ed25519_dalek::SigningKey;

use crate::config::Config;
use crate::delivery::Delivery;
use crate::store::Store;

pub struct AppState {
    pub config: Config,
    pub store: Store,
    pub delivery: Delivery,
    pub signing_key: SigningKey,
}

impl AppState {
    pub fn new(config: Config, store: Store) -> Self {
        let delivery = Delivery::new(
            config.interface_base_url.clone(),
            config.interface_token.clone(),
            &config.manifest_raw,
        );
        let signing_key = SigningKey::from_bytes(&config.signing_seed);
        Self { config, store, delivery, signing_key }
    }

    #[cfg(test)]
    pub fn for_tests(store: Store) -> Self {
        let manifest_raw = crate::testing::MANIFEST_JSON.as_bytes().to_vec();
        let manifest = serde_json::from_slice(&manifest_raw).expect("test manifest");
        let config = Config {
            bind_addr: "127.0.0.1:0".into(),
            store_path: ":memory:".into(),
            manifest_raw,
            manifest,
            signing_seed: [7u8; 32],
            interface_base_url: None,
            interface_token: None,
            interface_key: None,
            moderator_token: Some("test-token".into()),
            deadline_sweep_secs: 300,
        };
        Self::new(config, store)
    }
}
