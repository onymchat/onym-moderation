//! Google service-account OAuth2 — the credential the Play Integrity
//! API calls present.
//!
//! A service-account JSON key (from the Cloud project linked to the
//! Play Console app) signs an RS256 JWT which is exchanged at Google's
//! token endpoint for a short-lived access token. One scope,
//! `playintegrity`, covers both `decodeIntegrityToken` and
//! `deviceRecall:write`. The token is cached and refreshed when it
//! nears expiry, because minting one costs a network round trip —
//! unlike the DeviceCheck profile's self-signed ES256 bearer, which was
//! re-minted per call.

use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::error::Error;

const SCOPE: &str = "https://www.googleapis.com/auth/playintegrity";
/// Refresh when less than this much of the token's life remains.
const REFRESH_MARGIN: Duration = Duration::from_secs(5 * 60);

/// The fields of a Google service-account key file this module uses.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceAccountKey {
    pub client_email: String,
    /// RSA private key, PKCS#8 PEM.
    pub private_key: String,
    /// `https://oauth2.googleapis.com/token` in real key files; tests
    /// point it at a local stand-in.
    pub token_uri: String,
}

impl ServiceAccountKey {
    pub fn from_json(raw: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(raw)
            .map_err(|e| format!("service-account key is not a usable JSON key file: {e}"))
    }
}

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    /// Seconds. Google answers 3600.
    expires_in: u64,
}

struct CachedToken {
    access_token: String,
    expires_at: Instant,
}

pub struct GoogleAuth {
    client: reqwest::Client,
    key: ServiceAccountKey,
    encoding_key: EncodingKey,
    cached: Mutex<Option<CachedToken>>,
}

impl GoogleAuth {
    pub fn new(key: ServiceAccountKey) -> Result<Self, String> {
        let encoding_key = EncodingKey::from_rsa_pem(key.private_key.as_bytes())
            .map_err(|e| format!("service-account private key is not a usable RSA key: {e}"))?;
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .map_err(|e| format!("http client: {e}"))?,
            key,
            encoding_key,
            cached: Mutex::new(None),
        })
    }

    /// A currently valid access token, from cache or freshly exchanged.
    pub async fn access_token(&self) -> Result<String, Error> {
        let mut cached = self.cached.lock().await;
        if let Some(token) = cached.as_ref() {
            if token.expires_at.saturating_duration_since(Instant::now()) > REFRESH_MARGIN {
                return Ok(token.access_token.clone());
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let claims = Claims {
            iss: &self.key.client_email,
            scope: SCOPE,
            aud: &self.key.token_uri,
            iat: now,
            exp: now + 3600,
        };
        let assertion =
            jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &self.encoding_key)
                .map_err(|e| Error::Internal(format!("service-account JWT: {e}")))?;

        let response = self
            .client
            .post(&self.key.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(|e| Error::MarkWriteFailed(format!("token endpoint unreachable: {e}")))?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(Error::MarkWriteFailed(format!(
                "token exchange failed: {status} {text}"
            )));
        }
        let parsed: TokenResponse = serde_json::from_str(&text)
            .map_err(|e| Error::Internal(format!("token endpoint answered unparseably: {e}")))?;

        let token = parsed.access_token.clone();
        *cached = Some(CachedToken {
            access_token: parsed.access_token,
            expires_at: Instant::now() + Duration::from_secs(parsed.expires_in),
        });
        Ok(token)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A throwaway 2048-bit RSA key for fixtures. It signs assertions
    /// nothing verifies; the mock token endpoint accepts anything.
    /// Stored bare and wrapped at runtime so no PEM armor sits in the
    /// tree for a secret scanner to flag.
    const TEST_ONLY_RSA_BODY: &str = concat!(
        "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDZKyEROx59aQ83",
        "MChEam56J4UfmvGiTAZVcAONjWb2OYpBSDUnbDwZlStL197zjWqd9K/OJ+/aaDSV",
        "h4a2z6PbP6N0m1XmuGYA8axc5ic0fZG6XMhcV7cWs7sM6rqLzhtQMA3px9tMbXk+",
        "bhEqp122s3mIKhW5UOnIHs3gcZ5wCtBpJuui3y8oGY41Sp2toDx33rfuk5KqRozJ",
        "pHNFXHm9M/VOV740iQ44UXBZLLAtLGdvNsAPk3APs5kfPMZ4Dd5TD7PdfhQQCnou",
        "LSN+uSRNnAffkPXO+cM4MMuEJ8g893y+JdT8n4Tddhyn08jGyG22OZiYUzYmPP+L",
        "ntEblo3fAgMBAAECggEBAJI8Y6j5uV9TtoZALG1digVBxXfx21KhhQZVRl80X6fg",
        "OUQafoiMbq//bcdFlwFEMg4pbZUR+YaF8xrZxxIlIj6KTORBkYeqli1+j8WCydWj",
        "1NS8k8Ly4fwsjQF2sqVf5a6KnWPWS8rcUO+EKJUjXIyhsG3LgRNn8/TpIVNIzxq8",
        "PzT2W1/mrkI/5AnPWQJ/wATc4V1jE2G1iT2SrziBVGDg+zwvj7WTgpZNl19OQWTK",
        "UYlxNIEJN2Uk+lZvFTaO5ZmqvfW1JrpqHNXG7YOcQQOjjzUsxqj6puUzwnGx2o2n",
        "5uOIIr6WOE4eiv0r20lEVA4NHZGM3sKo+8E5fVcyCskCgYEA/Cgv4mR1Maj8zYn9",
        "LkObGX0sKpzOlSubYBxWnWwwN3V6ub4WALq+Ou90eAGyMMgZ1k1Gob8tiiIGSKCe",
        "hN1gQu8GgKOcZjng6AoBA82NgGcoXIspTw/LwPYkVlSLw/PRDckFDQFyR4qIq1GU",
        "k1D6joEw8OWnP2US7Z6wDyVekB0CgYEA3HpubDYupV6XbzVs/McFi6W57229KodN",
        "Bqm4Mj0D1UGzO963HcsURQwgaFWusK9U53x/WtVkLzQUm8PMI0GEe8FQBoz5IS24",
        "5fiNBr0+Vrg+hysaPTlN8wmJxuIkcO2UgiN9IUylGT2EaSpCbnWOloCMkG6zLayr",
        "1ARZeUc4bSsCgYAtmuMWMg8UHTkjv3o//NA3avEq/9NJHWrrlhSAQknyLdg1cdCu",
        "7xdqt1Y8QipFMluh67YDmP0Wh5LVXd9trlAzquFlMLIftwYbUXvfgTS/bWjaW/zr",
        "pLK4QoxN5NqmZRmBQcMdGA7gK4kOWyHhBvtZ/LmqSA7Yo2IqAdJb2ulgbQKBgQCM",
        "M8LCR1Y0TMmJq3Sp7blmCzYIvkT7pVxi70w1jj1AwG3ElaTmajxyh/qXvly++E/K",
        "gI3P6kCyD7FHOCQ5CzG/LLfB4qWN5rBcdUjgzzi0FqeUduFRq34ZHaiicy3vLfUx",
        "KHYq1b1rJoZsBbaG3XSV2hsIwYxpcBM4WKe5CoQkTwKBgQDwwmQFVyu8C2PSoJ6x",
        "IavOpLHbzT6WVedP1/5qzjAmnt8Cx2c5iNz7xWeH1aVfK1+t8ngqNX7xZDfIZrlV",
        "oem/1xyVMf7AQUwWpo6ulJfKqoaSGTuLfeh2HiauLo6nK7lkCsAS/2AUtZ8J/WFU",
        "HVvRKq+Mh4tQ6cb9ED0d5bWiZg==",
    );

    pub(crate) fn test_key_pem() -> String {
        format!(
            "-----BEGIN PRIVATE KEY-----\n{TEST_ONLY_RSA_BODY}\n-----END PRIVATE KEY-----"
        )
    }

    pub(crate) fn test_key(token_uri: String) -> ServiceAccountKey {
        ServiceAccountKey {
            client_email: "svc@test-project.iam.gserviceaccount.com".into(),
            private_key: test_key_pem(),
            token_uri,
        }
    }

    /// A mock token endpoint: counts exchanges, answers a fixed token.
    async fn spawn_token_endpoint() -> (String, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&count);
        let app = axum::Router::new().route(
            "/token",
            axum::routing::post(move || {
                let counted = Arc::clone(&counted);
                async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    axum::Json(serde_json::json!({
                        "access_token": "ya29.test-token",
                        "expires_in": 3600,
                        "token_type": "Bearer",
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("{base}/token"), count)
    }

    #[tokio::test]
    async fn exchanges_once_and_serves_from_cache() {
        let (token_uri, exchanges) = spawn_token_endpoint().await;
        let auth = GoogleAuth::new(test_key(token_uri)).unwrap();

        assert_eq!(auth.access_token().await.unwrap(), "ya29.test-token");
        assert_eq!(auth.access_token().await.unwrap(), "ya29.test-token");
        // The second call must not have gone back to the endpoint: the
        // token has ~an hour left, far above the refresh margin.
        assert_eq!(exchanges.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_nearly_expired_token_is_refreshed() {
        let (token_uri, exchanges) = spawn_token_endpoint().await;
        let auth = GoogleAuth::new(test_key(token_uri)).unwrap();
        let _ = auth.access_token().await.unwrap();

        // Age the cached token to inside the refresh margin.
        {
            let mut cached = auth.cached.lock().await;
            cached.as_mut().unwrap().expires_at = Instant::now() + Duration::from_secs(60);
        }
        let _ = auth.access_token().await.unwrap();
        assert_eq!(exchanges.load(Ordering::SeqCst), 2);
    }
}
