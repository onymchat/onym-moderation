//! Automated assessment against a locally-hosted moderation model.
//!
//! The model runs on the authority's own host. That is not an
//! optimisation: the evidence in a case is content a recipient
//! disclosed for adjudication, and sending it to somebody else's API
//! would be a further disclosure — one the manifest's confidentiality
//! policy would have to declare (§8 obligation 6), and one the
//! reference policy makes a consent-requiring change. Keeping inference
//! local means the disclosed content never leaves the operator who was
//! consented to.
//!
//! **Which** model is not this module's business. Everything
//! model-specific — prompt, output format, thresholds, category
//! mapping, what counts as invalid — lives in the consented
//! [`ModelProfile`](crate::profiles::ModelProfile). This module builds
//! the case document, makes one request, hands the output to the
//! profile, and records what came back. Supporting a seventh model is a
//! profile, not a patch.
//!
//! Two bounds hold whatever the profile says:
//!
//! 1. Every decision goes through `decisions::apply`, so it inherits
//!    the notice rule — a classifier cannot ban before the accused's
//!    consented response window has elapsed, however certain its score.
//! 2. Output the profile does not recognise is **no decision**, never a
//!    verdict. The tempting failure mode — unrecognised response, no
//!    categories, score zero, dismiss — would turn every outage into an
//!    acquittal, and its inverse would be far worse.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::casedoc;
use crate::config::{TriageConfig, TriageMode};
use crate::decisions::{self, Decider, Disposition};
use crate::error::Error;
use crate::profiles::{Adapter, Assessed, ModelOutput, ModelProfile, Outcome};
use crate::state::AppState;
use crate::store::CaseRecord;
use crate::util;

/// The record of one automated assessment.
///
/// Its fields are the ones the reference policy §4.2 requires a signed
/// verdict to identify: the policy digest, model profile digest, model
/// revision, class, input-evidence digest, raw final model output,
/// adapter outcome, and assessment time. Private chain-of-thought is
/// deliberately absent — it is neither a verdict reason nor evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Assessment {
    pub profile_id: String,
    pub profile_digest: String,
    pub policy_digest: String,
    pub repository: String,
    pub revision: String,
    pub class_id: String,
    /// SHA-256 of the exact case document the model was shown.
    pub input_digest: String,
    /// How much was in that document. An appeal turns on this more
    /// often than on the score: "did the model see my reply?" has a
    /// recorded answer rather than an inferred one.
    pub evidence_items: usize,
    pub response_items: usize,
    /// The model's final output, verbatim and bounded. Stored because a
    /// reviewer on appeal is entitled to see what the machine actually
    /// said, not a summary of it.
    pub raw_output: String,
    /// What the profile's adapter made of that output.
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    /// Why the adapter reached this outcome — in particular, why an
    /// output was rejected.
    pub note: String,
    pub assessed_at: String,
}

/// Model output beyond this is truncated before storage. A model that
/// returns a novel is a malfunctioning model, and the case file is not
/// the place to keep the novel.
const MAX_STORED_OUTPUT: usize = 8 * 1024;

pub struct Triage {
    client: reqwest::Client,
}

impl Triage {
    pub fn new(config: &TriageConfig) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(config.timeout_secs))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Assess one case and store the result.
    pub async fn assess(
        &self,
        state: &AppState,
        case: &CaseRecord,
        now: OffsetDateTime,
    ) -> Result<Assessment, Error> {
        let config = state
            .config
            .triage
            .as_ref()
            .ok_or_else(|| Error::Internal("triage is not configured".into()))?;
        let profile = &config.profile;

        // A profile that cannot decide this class must not be asked
        // about it. Its answer could not be attributed to terms the
        // accused consented to, and a request made anyway would put
        // disclosed evidence in front of a model for no purpose.
        if !profile.can_decide(&case.class_id) {
            let document = casedoc::build(&state.store, case)?;
            return self.record(
                state,
                case,
                profile,
                "",
                &document,
                Assessed {
                    outcome: Outcome::NoDecision,
                    score: None,
                    labels: Vec::new(),
                    note: format!(
                        "profile {} has no rule or native category for class {:?}; it cannot \
                         decide this case",
                        profile.id, case.class_id
                    ),
                },
                now,
            );
        }

        let document = casedoc::build(&state.store, case)?;
        if document.evidence_items == 0 {
            // Recorded, not returned as an error. A case with no
            // evidence will never acquire any, so retrying it forever
            // is pure noise; recording a no-decision lets the attempt
            // counter carry it to its decision deadline, where it is
            // dismissed.
            return self.record(
                state,
                case,
                profile,
                "",
                &document,
                Assessed {
                    outcome: Outcome::NoDecision,
                    score: None,
                    labels: Vec::new(),
                    note: format!(
                        "case {} has no stored evidence to classify",
                        case.case_id
                    ),
                },
                now,
            );
        }

        let body = profile
            .request_body(&case.class_id, &document.text)
            .map_err(Error::Internal)?;

        // A failed round-trip is an *attempt*, and has to be recorded
        // as one. Returning early here meant no `assessments` row was
        // written, so the case came back with `attempts = 0` on the
        // next sweep — and the backoff and the give-up counter, which
        // exist for exactly this failure, never applied to it. A model
        // that was down got re-hit for every due case, every tick,
        // until each case's decision deadline.
        let output = match self.infer(config, body).await {
            Ok(output) => output,
            Err(e) => {
                let assessment = self.record(
                    state,
                    case,
                    profile,
                    "",
                    &document,
                    Assessed {
                        outcome: Outcome::NoDecision,
                        score: None,
                        labels: Vec::new(),
                        note: format!("the model could not be consulted: {e}"),
                    },
                    now,
                )?;
                // Still an error to the caller: nothing was decided,
                // and the log should say the model failed rather than
                // that it declined to decide.
                tracing::warn!(case_id = %case.case_id, error = %e, "inference failed; attempt recorded");
                let _ = assessment;
                return Err(e);
            }
        };
        let assessed = profile.evaluate(&case.class_id, &output);

        self.record(state, case, profile, &output.text, &document, assessed, now)
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        state: &AppState,
        case: &CaseRecord,
        profile: &ModelProfile,
        raw_output: &str,
        document: &casedoc::CaseDocument,
        assessed: Assessed,
        now: OffsetDateTime,
    ) -> Result<Assessment, Error> {
        let assessment = Assessment {
            profile_id: profile.id.clone(),
            profile_digest: profile.profile_digest.clone(),
            policy_digest: profile.policy_digest.clone(),
            repository: profile.repository.clone(),
            revision: profile.revision.clone(),
            class_id: case.class_id.clone(),
            input_digest: document.digest.clone(),
            evidence_items: document.evidence_items,
            response_items: document.response_items,
            raw_output: truncate(raw_output, MAX_STORED_OUTPUT),
            outcome: assessed.outcome.as_str().to_string(),
            score: assessed.score,
            labels: assessed.labels,
            note: assessed.note,
            assessed_at: util::format_timestamp(now),
        };

        let raw = serde_json::to_vec(&assessment)
            .map_err(|e| Error::Internal(format!("encode assessment: {e}")))?;
        state.store.put_assessment(&case.case_id, &raw, &assessment.outcome)?;
        state.store.append_event_bounded(
            &case.case_id,
            &util::format_timestamp(now),
            "triage_assessed",
            &format!("{} by {} ({})", assessment.outcome, profile.id, assessment.note),
            128,
        )?;
        Ok(assessment)
    }

    /// One request to the local inference server, which speaks the
    /// OpenAI-compatible chat-completions shape that llama.cpp, vLLM,
    /// Ollama and TGI all serve. The profile decided what is in the
    /// body; this only sends it and reads the answer out.
    async fn infer(&self, config: &TriageConfig, body: Value) -> Result<ModelOutput, Error> {
        let mut request = self.client.post(&config.url).json(&body);
        if let Some(key) = config.api_key.as_deref() {
            request = request.bearer_auth(key);
        }

        let response = request.send().await.map_err(|e| {
            Error::Internal(format!("moderation model unreachable at {}: {e}", config.url))
        })?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(Error::Internal(format!(
                "moderation model returned {status}: {}",
                truncate(&text, 512)
            )));
        }

        let value: Value = serde_json::from_str(&text)
            .map_err(|e| Error::Internal(format!("moderation response is not JSON: {e}")))?;

        parse_completion(&value).ok_or_else(|| {
            Error::Internal(format!(
                "moderation response had no readable completion: {}",
                truncate(&text, 512)
            ))
        })
    }
}

/// Read the final output and, when present, the first token's log
/// probabilities out of a chat-completions response.
///
/// A reasoning channel is skipped where the server separates it:
/// private chain-of-thought is not the answer, and reading it as one
/// would let a model's musings decide a case its final output declined
/// to decide.
fn parse_completion(value: &Value) -> Option<ModelOutput> {
    let choice = value.get("choices")?.as_array()?.first()?;
    let message = choice.get("message")?;
    let text = message
        .get("content")
        .and_then(Value::as_str)
        .map(str::to_string)
        // Some servers return `content: null` alongside a reasoning
        // field. An empty final channel is still a readable response —
        // the adapter decides what to make of it.
        .unwrap_or_default();

    let mut first_token_logprobs = Vec::new();
    if let Some(content) = choice.get("logprobs").and_then(|l| l.get("content")).and_then(Value::as_array) {
        if let Some(first) = content.first() {
            // The chosen token, plus the alternatives the server was
            // asked to report. Both matter: the answer token may not be
            // the top one.
            if let (Some(token), Some(logprob)) = (
                first.get("token").and_then(Value::as_str),
                first.get("logprob").and_then(Value::as_f64),
            ) {
                first_token_logprobs.push((token.to_string(), logprob));
            }
            if let Some(top) = first.get("top_logprobs").and_then(Value::as_array) {
                for entry in top {
                    if let (Some(token), Some(logprob)) = (
                        entry.get("token").and_then(Value::as_str),
                        entry.get("logprob").and_then(Value::as_f64),
                    ) {
                        first_token_logprobs.push((token.to_string(), logprob));
                    }
                }
            }
        }
    }

    Some(ModelOutput { text, first_token_logprobs })
}

fn truncate(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_string();
    }
    let mut end = limit;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[truncated]", &value[..end])
}

/// Assess a case whose response window has closed, and in autonomous
/// mode act on the result.
///
/// Timing is policy, not scheduling convenience: §4.1 says the
/// authority assesses the *completed* case document after the response
/// window. Assessing on arrival would ask the model about a case the
/// accused had not yet had the chance to answer, and then decide it on
/// that reading.
pub async fn assess_and_maybe_decide(state: &AppState, case_id: &str, now: OffsetDateTime) {
    let Some(triage) = state.triage.as_ref() else { return };
    let Some(config) = state.config.triage.as_ref() else { return };

    let case = match state.store.case(case_id) {
        Ok(Some(case)) => case,
        Ok(None) => return,
        Err(e) => {
            tracing::error!(%case_id, error = %e, "triage could not load the case");
            return;
        }
    };
    if case.stage != "open" {
        return;
    }
    if !response_window_closed(&case, now) {
        return;
    }

    let assessment = match triage.assess(state, &case, now).await {
        Ok(assessment) => assessment,
        Err(e) => {
            // The case is untouched and still open. The sweep retries,
            // and failing that the decision deadline dismisses it — an
            // authority whose classifier is down does not get to hold
            // anyone.
            tracing::error!(%case_id, error = %e, "triage failed; case left open");
            return;
        }
    };

    if config.mode != TriageMode::Autonomous {
        return;
    }

    match Outcome::parse(&assessment.outcome) {
        Outcome::Dismiss => {
            apply_automated(state, case_id, Disposition::Dismiss, &assessment, now).await;
        }
        Outcome::Ban => {
            apply_automated(state, case_id, Disposition::Ban, &assessment, now).await;
        }
        Outcome::NoDecision => {
            tracing::info!(%case_id, note = %assessment.note, "no automated decision; case left open");
        }
    }
}

fn response_window_closed(case: &CaseRecord, now: OffsetDateTime) -> bool {
    match util::parse_timestamp(&case.response_deadline) {
        Ok(deadline) => now >= deadline,
        // An unparseable deadline is a corrupt case, not an open
        // season. Refuse to assess it and let a human find it.
        Err(_) => false,
    }
}

async fn apply_automated(
    state: &AppState,
    case_id: &str,
    disposition: Disposition,
    assessment: &Assessment,
    now: OffsetDateTime,
) {
    // The reasoning is a content address of the stored assessment, so
    // the accused (and an appellate) can be shown exactly what was
    // decided on rather than a sentence about it.
    let reasoning = match state.store.assessment(case_id) {
        Ok(Some((raw, _))) => format!("sha256:{}", util::sha256_hex(&raw)),
        _ => format!("automated assessment: {} ({})", assessment.outcome, assessment.note),
    };

    match decisions::apply(state, case_id, disposition, &reasoning, Decider::Automated, now).await {
        Ok(issued) => {
            let _ = state.store.mark_assessment_applied(case_id);
            tracing::info!(%case_id, verdict_ref = %issued.verdict_ref, "automated decision applied");
        }
        Err(Error::CaseState(reason)) | Err(Error::WindowClosed(reason)) => {
            // The guards in `decisions.rs` had the last word, as they
            // should. Nothing to retry.
            tracing::info!(%case_id, %reason, "automated decision refused by the decision guards");
        }
        Err(e) => tracing::error!(%case_id, error = %e, "automated decision failed"),
    }
}

/// Whether a profile is safe to run against this manifest, checked at
/// boot rather than at the first case.
///
/// A class the profile cannot decide is not fatal — those cases simply
/// wait for a human — but it is exactly the kind of misconfiguration
/// that looks like "the classifier is quiet lately".
pub fn unmappable_classes(profile: &ModelProfile, manifest: &crate::types::AuthorityManifest) -> Vec<String> {
    manifest
        .violation_classes
        .iter()
        .filter(|class| !profile.can_decide(&class.class_id))
        .map(|class| class.class_id.clone())
        .collect()
}

/// Whether the profile needs log probabilities from the server, so a
/// deployment can be told before it discovers it case by case.
pub fn needs_logprobs(profile: &ModelProfile) -> bool {
    matches!(profile.adapter, Adapter::FirstTokenScore { .. })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_final_message_out_of_a_chat_completion() {
        let value: Value = serde_json::from_str(
            r#"{"choices":[{"message":{"role":"assistant","content":"unsafe\nS4"}}]}"#,
        )
        .unwrap();
        let output = parse_completion(&value).unwrap();
        assert_eq!(output.text, "unsafe\nS4");
        assert!(output.first_token_logprobs.is_empty());
    }

    #[test]
    fn reads_first_token_log_probabilities_including_alternatives() {
        let value: Value = serde_json::from_str(
            r#"{"choices":[{"message":{"content":"yes"},"logprobs":{"content":[
                 {"token":"yes","logprob":-0.1,"top_logprobs":[
                   {"token":"yes","logprob":-0.1},{"token":"no","logprob":-2.3}]}]}}]}"#,
        )
        .unwrap();
        let output = parse_completion(&value).unwrap();
        assert!(output.first_token_logprobs.iter().any(|(t, _)| t == "yes"));
        assert!(
            output.first_token_logprobs.iter().any(|(t, _)| t == "no"),
            "the alternative must be read: the answer token is not always the top one"
        );
    }

    /// A server that returns only a reasoning channel has not answered.
    /// Reading the reasoning as the answer would let a model's musings
    /// decide a case its final output declined to decide.
    #[test]
    fn a_reasoning_only_response_yields_an_empty_final_output() {
        let value: Value = serde_json::from_str(
            r#"{"choices":[{"message":{"content":null,"reasoning":"the document mentions..."}}]}"#,
        )
        .unwrap();
        let output = parse_completion(&value).unwrap();
        assert_eq!(output.text, "");
        assert!(!output.text.contains("document mentions"));
    }

    #[test]
    fn a_response_with_no_choices_is_unreadable() {
        let value: Value = serde_json::from_str(r#"{"error":{"message":"model not loaded"}}"#).unwrap();
        assert!(parse_completion(&value).is_none());
    }

    #[test]
    fn stored_output_is_bounded() {
        let long = "x".repeat(MAX_STORED_OUTPUT * 2);
        let stored = truncate(&long, MAX_STORED_OUTPUT);
        assert!(stored.len() < long.len());
        assert!(stored.ends_with("…[truncated]"));
    }

    #[test]
    fn truncation_does_not_split_a_character() {
        let text = "é".repeat(64);
        let stored = truncate(&text, 7);
        assert!(stored.starts_with("ééé"));
    }

    /// The window rule again, at the point where automation would
    /// otherwise sidestep it: a case is not even assessed until the
    /// accused's time to answer has run out, because the document the
    /// model is shown must be the completed one.
    #[test]
    fn a_case_inside_its_response_window_is_not_assessed() {
        let mut case = crate::store::CaseRecord {
            case_id: "c1".into(),
            accused: "onym:key:acc".into(),
            reporter: "onym:key:rep".into(),
            class_id: "csam".into(),
            mandate_ref: "m1".into(),
            device_binding: "d1".into(),
            stage: "open".into(),
            opened_at: "2026-08-01T00:00:00Z".into(),
            response_deadline: "2026-08-04T00:00:00Z".into(),
            decision_deadline: "2026-08-08T00:00:00Z".into(),
            responded: false,
            disposition: None,
            appeal_deadline: None,
            appeal_state: "none".into(),
        };
        let inside = util::parse_timestamp("2026-08-02T00:00:00Z").unwrap();
        let after = util::parse_timestamp("2026-08-05T00:00:00Z").unwrap();
        assert!(!response_window_closed(&case, inside));
        assert!(response_window_closed(&case, after));

        // Answering does not bring the assessment forward either.
        case.responded = true;
        assert!(!response_window_closed(&case, inside));

        // A corrupt deadline refuses rather than opening the door.
        case.response_deadline = "not a timestamp".into();
        assert!(!response_window_closed(&case, after));
    }

    // ─── End to end, against a stub inference server ─────────────────

    /// Serve one canned chat-completion and record what was asked.
    async fn stub_model(response: serde_json::Value) -> (String, std::sync::Arc<std::sync::Mutex<Vec<Value>>>) {
        use axum::routing::post;

        let seen: std::sync::Arc<std::sync::Mutex<Vec<Value>>> = Default::default();
        let recorder = seen.clone();
        let app = axum::Router::new().route(
            "/v1/chat/completions",
            post(move |axum::Json(body): axum::Json<Value>| {
                let recorder = recorder.clone();
                let response = response.clone();
                async move {
                    recorder.lock().unwrap().push(body);
                    axum::Json(response)
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}/v1/chat/completions"), seen)
    }

    fn open_case(store: &crate::store::Store, class_id: &str, response_deadline: &str) -> CaseRecord {
        let case = CaseRecord {
            case_id: "c1".into(),
            accused: "onym:key:acc".into(),
            reporter: "onym:key:rep".into(),
            class_id: class_id.into(),
            mandate_ref: "m1".into(),
            device_binding: "d1".into(),
            stage: "open".into(),
            opened_at: "2026-08-01T00:00:00Z".into(),
            response_deadline: response_deadline.into(),
            decision_deadline: "2026-08-30T00:00:00Z".into(),
            responded: false,
            disposition: None,
            appeal_deadline: None,
            appeal_state: "none".into(),
        };
        store.put_case(&case).unwrap();
        let report = serde_json::json!({
            "reportVersion": 1, "reportId": "r1", "reporter": "onym:key:rep",
            "reporterMandate": "m0", "accused": "onym:key:acc", "classId": class_id,
            "evidence": [{"disclosedContent": "the material", "authenticityProof": "sig"}],
            "filedAt": "2026-08-02T00:00:00Z",
        });
        store
            .put_report("r1", "onym:key:rep", "onym:key:acc", class_id, Some("c1"), 1.0,
                        &serde_json::to_vec(&report).unwrap(), "2026-08-02T00:00:00Z")
            .unwrap();
        case
    }

    /// The whole path for a native-taxonomy profile: build the
    /// document, call the server, read the label, ban.
    #[tokio::test]
    async fn a_native_taxonomy_profile_decides_end_to_end() {
        let (url, seen) = stub_model(serde_json::json!({
            "choices": [{"message": {"role": "assistant",
                                     "content": "Safety: Unsafe\nCategories: Violent"}}]
        }))
        .await;
        let store = crate::store::Store::in_memory().unwrap();
        open_case(&store, "credible-violence", "2026-08-04T00:00:00Z");
        let state =
            AppState::for_tests_with_triage(store, "qwen3guard-8b", &url, TriageMode::Autonomous);
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();

        assess_and_maybe_decide(&state, "c1", now).await;

        let case = state.store.case("c1").unwrap().unwrap();
        assert_eq!(case.disposition.as_deref(), Some("ban"), "expected an automated ban");

        // The model was sent the case document, and no canonical rule:
        // this profile applies its own taxonomy.
        let request = &seen.lock().unwrap()[0];
        let sent = request["messages"][0]["content"].as_str().unwrap();
        assert!(sent.contains("CLASS: credible-violence"));
        assert!(sent.contains("the material"));
        assert!(!sent.contains("R-VIOLENCE"), "a native-taxonomy profile gets no canonical rule");

        // The verdict's reasoning is the content address of the stored
        // assessment, and the assessment records what a reviewer needs.
        let (raw, applied) = state.store.assessment("c1").unwrap().unwrap();
        assert!(applied);
        let assessment: Assessment = serde_json::from_slice(&raw).unwrap();
        assert_eq!(assessment.profile_id, "qwen3guard-8b");
        assert_eq!(assessment.revision, "4505cb1a6f1864f21f8b27f7daf1b9a1aab6edbb");
        assert_eq!(assessment.raw_output, "Safety: Unsafe\nCategories: Violent");
        assert_eq!(assessment.outcome, "ban");
        assert!(assessment.score.is_none(), "a label profile invents no score");
        assert_eq!(assessment.input_digest.len(), 64);
    }

    /// And for a scoring profile, with the rule actually reaching the
    /// model.
    #[tokio::test]
    async fn a_scoring_profile_decides_end_to_end_on_the_canonical_rule() {
        let (url, seen) = stub_model(serde_json::json!({
            "choices": [{"message": {"content": "no"}, "logprobs": {"content": [
                {"token": "no", "logprob": -0.01, "top_logprobs": [
                    {"token": "no", "logprob": -0.01}, {"token": "yes", "logprob": -6.0}]}]}}]
        }))
        .await;
        let store = crate::store::Store::in_memory().unwrap();
        open_case(&store, "csam", "2026-08-04T00:00:00Z");
        let state =
            AppState::for_tests_with_triage(store, "shieldstral-3b", &url, TriageMode::Autonomous);
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();

        assess_and_maybe_decide(&state, "c1", now).await;

        assert_eq!(
            state.store.case("c1").unwrap().unwrap().disposition.as_deref(),
            Some("dismiss")
        );
        let request = &seen.lock().unwrap()[0];
        assert_eq!(request["logprobs"], true, "a scoring profile must ask for log probabilities");
        let user = request["messages"][1]["content"].as_str().unwrap();
        assert!(user.contains("R-CSAM"), "the consented rule must reach the model");

        let (raw, _) = state.store.assessment("c1").unwrap().unwrap();
        let assessment: Assessment = serde_json::from_slice(&raw).unwrap();
        assert!(assessment.score.unwrap() < 0.2);
    }

    /// The failure that matters: a server returning something the
    /// profile cannot read must leave the case open, not dismiss it.
    #[tokio::test]
    async fn an_unreadable_model_response_decides_nothing() {
        let (url, _) = stub_model(serde_json::json!({
            "choices": [{"message": {"content": "I'm not able to help with that request."}}]
        }))
        .await;
        let store = crate::store::Store::in_memory().unwrap();
        open_case(&store, "csam", "2026-08-04T00:00:00Z");
        let state =
            AppState::for_tests_with_triage(store, "qwen3guard-8b", &url, TriageMode::Autonomous);
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();

        assess_and_maybe_decide(&state, "c1", now).await;

        let case = state.store.case("c1").unwrap().unwrap();
        assert_eq!(case.stage, "open", "an unreadable answer is not an acquittal");
        assert!(case.disposition.is_none());
        assert!(state.store.undelivered_verdicts().unwrap().is_empty());
    }

    /// Advisory mode classifies and stops. The recommendation is
    /// recorded for a moderator; nothing moves on its own.
    #[tokio::test]
    async fn advisory_mode_records_but_does_not_decide() {
        let (url, _) = stub_model(serde_json::json!({
            "choices": [{"message": {"content": "Safety: Unsafe\nCategories: Violent"}}]
        }))
        .await;
        let store = crate::store::Store::in_memory().unwrap();
        open_case(&store, "credible-violence", "2026-08-04T00:00:00Z");
        let state =
            AppState::for_tests_with_triage(store, "qwen3guard-8b", &url, TriageMode::Advisory);
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();

        assess_and_maybe_decide(&state, "c1", now).await;

        assert_eq!(state.store.case("c1").unwrap().unwrap().stage, "open");
        let (raw, applied) = state.store.assessment("c1").unwrap().unwrap();
        assert!(!applied);
        let assessment: Assessment = serde_json::from_slice(&raw).unwrap();
        assert_eq!(assessment.outcome, "ban", "the recommendation is recorded either way");
    }

    /// The accused's reply is in the document the model is shown. This
    /// is the reason assessment waits for the window at all.
    #[tokio::test]
    async fn the_accused_response_reaches_the_model() {
        let (url, seen) = stub_model(serde_json::json!({
            "choices": [{"message": {"content": "Safety: Safe\nCategories: None"}}]
        }))
        .await;
        let store = crate::store::Store::in_memory().unwrap();
        let mut case = open_case(&store, "credible-violence", "2026-08-04T00:00:00Z");
        case.responded = true;
        let reply = serde_json::json!({"caseId": "c1", "statement": "it is a song lyric"});
        store
            .put_response(&crate::store::ResponseFiling { case: &case, raw: &serde_json::to_vec(&reply).unwrap(), late: false, filed_at: "2026-08-03T00:00:00Z", event_kind: "response", event_detail: "it is a song lyric", limit: 32 })
            .unwrap();

        let state =
            AppState::for_tests_with_triage(store, "qwen3guard-8b", &url, TriageMode::Autonomous);
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();
        assess_and_maybe_decide(&state, "c1", now).await;

        let sent = seen.lock().unwrap()[0]["messages"][0]["content"].as_str().unwrap().to_string();
        assert!(sent.contains("it is a song lyric"), "the reply must be in the document");
        assert!(!sent.contains("ACCUSED RESPONSE:\nNONE"));
        assert_eq!(
            state.store.case("c1").unwrap().unwrap().disposition.as_deref(),
            Some("dismiss")
        );
    }

    #[test]
    fn classes_the_profile_cannot_decide_are_reported_at_boot() {
        let manifest: crate::types::AuthorityManifest =
            serde_json::from_str(crate::testing::MANIFEST_JSON).unwrap();
        let profile = crate::profiles::by_id("qwen3guard-8b").unwrap();
        // The test manifest declares only classes the reference
        // profiles map.
        assert!(unmappable_classes(&profile, &manifest).is_empty());

        let mut narrowed = profile.clone();
        if let Adapter::NativeTaxonomy { required_code, .. } = &mut narrowed.adapter {
            required_code.remove("csam");
        }
        assert_eq!(unmappable_classes(&narrowed, &manifest), vec!["csam".to_string()]);
    }

    /// The failure the backoff and the give-up counter were written
    /// for, and the one they did not cover. A failed round-trip
    /// returned early without writing an assessment row, so the case
    /// came back with `attempts = 0` every sweep: no backoff, no cap,
    /// and a model that was down got re-hit for every due case until
    /// each case's decision deadline.
    #[tokio::test]
    async fn a_failed_inference_records_an_attempt() {
        let store = crate::store::Store::in_memory().unwrap();
        open_case(&store, "csam", "2026-08-04T00:00:00Z");
        // A port nothing is listening on.
        let state = AppState::for_tests_with_triage(
            store,
            "qwen3guard-8b",
            "http://127.0.0.1:1/v1/chat/completions",
            TriageMode::Autonomous,
        );
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();

        assess_and_maybe_decide(&state, "c1", now).await;

        let (raw, applied) = state
            .store
            .assessment("c1")
            .unwrap()
            .expect("a failed attempt is still an attempt, and has to be on file");
        assert!(!applied);
        let assessment: Assessment = serde_json::from_slice(&raw).unwrap();
        assert_eq!(assessment.outcome, "no-decision");
        assert!(
            assessment.note.contains("could not be consulted"),
            "the record must say the model failed, not that it declined: {}",
            assessment.note
        );

        // And the case is still open, still due — but now carrying an
        // attempt, so the sweep can space the next one out.
        let due = state.store.cases_awaiting_assessment("2026-08-10T00:00:00Z").unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].1, 1, "the attempt was counted");
        assert!(due[0].2.is_some(), "and timestamped, so backoff has something to measure");
    }

    /// A case with no evidence will never acquire any, so retrying it
    /// until its deadline is noise. It is recorded as a no-decision and
    /// carried to the deadline by the attempt counter.
    #[tokio::test]
    async fn a_case_with_no_evidence_is_recorded_not_retried_forever() {
        let store = crate::store::Store::in_memory().unwrap();
        let case = CaseRecord {
            case_id: "c1".into(),
            accused: "onym:key:acc".into(),
            reporter: "onym:key:rep".into(),
            class_id: "csam".into(),
            mandate_ref: "m1".into(),
            device_binding: "d1".into(),
            stage: "open".into(),
            opened_at: "2026-08-01T00:00:00Z".into(),
            response_deadline: "2026-08-04T00:00:00Z".into(),
            decision_deadline: "2026-08-30T00:00:00Z".into(),
            responded: false,
            disposition: None,
            appeal_deadline: None,
            appeal_state: "none".into(),
        };
        store.put_case(&case).unwrap();
        let state = AppState::for_tests_with_triage(
            store,
            "qwen3guard-8b",
            "http://127.0.0.1:1/v1/chat/completions",
            TriageMode::Autonomous,
        );
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();

        assess_and_maybe_decide(&state, "c1", now).await;

        let (raw, _) = state.store.assessment("c1").unwrap().expect("recorded");
        let assessment: Assessment = serde_json::from_slice(&raw).unwrap();
        assert_eq!(assessment.outcome, "no-decision");
        assert!(assessment.note.contains("no stored evidence"), "{}", assessment.note);
        assert_eq!(state.store.case("c1").unwrap().unwrap().stage, "open");
    }

}
