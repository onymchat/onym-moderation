//! Shared application state.

use ed25519_dalek::SigningKey;
use time::OffsetDateTime;

use crate::config::Config;
use crate::delivery::Delivery;
use crate::store::Store;
use crate::triage::Triage;

/// The clock a decision is timed against.
///
/// It exists because one caller cannot use a timestamp handed to it.
/// The triage sweep reads the clock once, then awaits a model that may
/// take two minutes per case for up to twenty-five cases; a decision
/// guarded by that timestamp is guarded by when the sweep *started*,
/// which is how a ban committed after the decision deadline had passed.
/// The guard has to read the clock itself — and a guard that reads the
/// clock itself is untestable unless the clock can be pinned.
pub enum Clock {
    System,
    #[cfg(test)]
    Pinned(std::sync::Mutex<OffsetDateTime>),
}

impl Clock {
    pub fn now(&self) -> OffsetDateTime {
        match self {
            Clock::System => OffsetDateTime::now_utc(),
            #[cfg(test)]
            Clock::Pinned(at) => *at.lock().unwrap(),
        }
    }

    /// Move a pinned clock, so a test can put time between a model
    /// answering and the decision it produced being committed.
    #[cfg(test)]
    pub fn set(&self, at: OffsetDateTime) {
        match self {
            Clock::System => panic!("cannot move the system clock"),
            Clock::Pinned(pinned) => *pinned.lock().unwrap() = at,
        }
    }
}

pub struct AppState {
    pub config: Config,
    pub store: Store,
    pub delivery: Delivery,
    pub signing_key: SigningKey,
    /// Present only when a classifier is configured.
    pub triage: Option<Triage>,
    pub clock: Clock,
}

impl AppState {
    /// The time *now*, for a guard that must not be handed a timestamp
    /// read before an awaited call.
    pub fn now(&self) -> OffsetDateTime {
        self.clock.now()
    }

    pub fn new(config: Config, store: Store) -> Self {
        let delivery = Delivery::new(
            config.interface_base_url.clone(),
            config.interface_token.clone(),
            config.interface_routes.clone(),
            &config.manifest_raw,
        );
        let signing_key = SigningKey::from_bytes(&config.signing_seed);
        let triage = config.triage.as_ref().map(Triage::new);
        Self { config, store, delivery, signing_key, triage, clock: Clock::System }
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
            interface_routes: Default::default(),
            interface_keys_by_component: Default::default(),
            // Tests exercise the fail-closed path deliberately, so the
            // default fixture is a *configured* deployment; the
            // unconfigured one gets its own test.
            interface_keys: vec![crate::testing::interface_key_reference()],
            moderator_token: Some("test-token".into()),
            deadline_sweep_secs: 300,
            triage: None,
            admin_token: Some("test-admin".into()),
            allow_early_ban_for_qa: false,
        };
        let mut state = Self::new(config, store);
        // Pinned to the instant every test that injects a `now` uses,
        // so a guard reading the clock and a caller passing a timestamp
        // agree unless a test deliberately moves one of them.
        state.clock = Clock::Pinned(std::sync::Mutex::new(
            crate::util::parse_timestamp("2026-08-10T00:00:00Z").expect("fixture timestamp"),
        ));
        state
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
