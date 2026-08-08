//! Automated triage against a locally-hosted Mistral moderation model.
//!
//! The model runs on the authority's own host. That is not an
//! optimisation: the evidence in a case is content a recipient
//! disclosed for adjudication, and sending it to somebody else's API
//! would be a further disclosure — one the manifest's confidentiality
//! policy would have to declare (§8 obligation 6). Keeping inference
//! local means the disclosed content never leaves the operator who was
//! consented to.
//!
//! What the classifier may do is bounded in two ways that matter:
//!
//! 1. Every decision it reaches goes through `decisions::apply`, so it
//!    inherits the notice rule — a classifier cannot ban before the
//!    accused's consented response window closes, however certain its
//!    scores are.
//! 2. A response it cannot parse is an **error**, never a clean
//!    result. The failure mode of "unrecognised JSON → no categories →
//!    score 0 → dismiss" would quietly turn every outage into an
//!    acquittal, and the inverse would be worse.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::config::{TriageConfig, TriageMode};
use crate::decisions::{self, Decider, Disposition};
use crate::error::Error;
use crate::state::AppState;
use crate::store::CaseRecord;
use crate::util;

/// What the classifier concluded about a case.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Assessment {
    pub model: String,
    /// Every category the model reported, with its score, in the order
    /// the model gave them. Stored whole: an assessment that only kept
    /// the deciding number would be unreviewable on appeal.
    pub categories: Vec<CategoryScore>,
    /// The highest score among the categories this case's violation
    /// class actually maps to.
    pub relevant_score: f64,
    /// Which categories those were, so a reviewer can see what the
    /// class was judged by.
    pub relevant_categories: Vec<String>,
    pub recommendation: String,
    pub assessed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryScore {
    pub category: String,
    pub score: f64,
    /// Present when the model reports a boolean judgment alongside the
    /// score.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violated: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recommendation {
    Ban,
    Dismiss,
    /// Between the thresholds: the classifier declines to decide, and
    /// the case waits for a human or for the decision deadline.
    Inconclusive,
}

impl Recommendation {
    pub fn as_str(self) -> &'static str {
        match self {
            Recommendation::Ban => "ban",
            Recommendation::Dismiss => "dismiss",
            Recommendation::Inconclusive => "inconclusive",
        }
    }

    pub fn parse(raw: &str) -> Self {
        match raw {
            "ban" => Recommendation::Ban,
            "dismiss" => Recommendation::Dismiss,
            _ => Recommendation::Inconclusive,
        }
    }
}

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

    /// Classify one case's evidence and store the assessment.
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

        let evidence = state.store.evidence_for_case(&case.case_id)?;
        if evidence.is_empty() {
            return Err(Error::Internal(format!(
                "case {} has no stored evidence to classify",
                case.case_id
            )));
        }

        let scores = self.classify(config, &evidence).await?;

        // Only the categories this class maps to bear on it. Scoring a
        // case for `unsolicited-pornography` on a `financial` category
        // would be judging conduct nobody consented to have judged.
        let relevant_categories = config
            .category_map
            .get(&case.class_id)
            .cloned()
            .unwrap_or_default();
        let relevant_score = scores
            .iter()
            .filter(|s| relevant_categories.iter().any(|c| c == &s.category))
            .map(|s| s.score)
            .fold(0.0_f64, f64::max);

        // An unmapped class cannot be scored at all — better to be
        // inconclusive than to invent a number for terms the mapping
        // never covered.
        let recommendation = if relevant_categories.is_empty() {
            tracing::warn!(
                class_id = %case.class_id,
                "no triage category mapping for this class; recommending nothing"
            );
            Recommendation::Inconclusive
        } else if relevant_score >= config.ban_threshold {
            Recommendation::Ban
        } else if relevant_score <= config.dismiss_threshold {
            Recommendation::Dismiss
        } else {
            Recommendation::Inconclusive
        };

        let assessment = Assessment {
            model: config.model.clone(),
            categories: scores,
            relevant_score,
            relevant_categories,
            recommendation: recommendation.as_str().to_string(),
            assessed_at: util::format_timestamp(now),
        };

        let raw = serde_json::to_vec(&assessment)
            .map_err(|e| Error::Internal(format!("encode assessment: {e}")))?;
        state.store.put_assessment(&case.case_id, &raw, recommendation.as_str())?;
        state.store.append_event(
            &case.case_id,
            &util::format_timestamp(now),
            "triage_assessed",
            &format!("{} ({:.3})", recommendation.as_str(), assessment.relevant_score),
        )?;

        Ok(assessment)
    }

    /// POST the disclosed content to the moderation endpoint and
    /// normalize whatever shape comes back.
    async fn classify(
        &self,
        config: &TriageConfig,
        inputs: &[String],
    ) -> Result<Vec<CategoryScore>, Error> {
        let mut request = self
            .client
            .post(&config.url)
            .json(&serde_json::json!({ "model": config.model, "input": inputs }));
        if let Some(key) = config.api_key.as_deref() {
            request = request.bearer_auth(key);
        }

        let response = request
            .send()
            .await
            .map_err(|e| Error::Internal(format!("moderation model unreachable at {}: {e}", config.url)))?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(Error::Internal(format!("moderation model returned {status}: {body}")));
        }

        let value: Value = serde_json::from_str(&body)
            .map_err(|e| Error::Internal(format!("moderation response is not JSON: {e}")))?;

        parse_scores(&value).ok_or_else(|| {
            // Deliberately an error. See the module comment: an
            // unrecognised response must not read as "nothing found".
            Error::Internal(format!(
                "moderation response had no recognisable category scores: {body}"
            ))
        })
    }
}

/// Normalize the shapes this API has used.
///
/// Two are known: the older `results[].category_scores` map, and the
/// newer `guardrails[].<guard>.categories` map of
/// `{score, violated}`. Both are accepted because a deployment may
/// pin either, and guessing wrong silently would be worse than
/// supporting both.
fn parse_scores(value: &Value) -> Option<Vec<CategoryScore>> {
    if let Some(scores) = parse_results_shape(value) {
        return Some(scores);
    }
    parse_guardrails_shape(value)
}

/// `{"results":[{"categories":{...bool}, "category_scores":{...float}}]}`
fn parse_results_shape(value: &Value) -> Option<Vec<CategoryScore>> {
    let results = value.get("results")?.as_array()?;
    let mut best: std::collections::BTreeMap<String, CategoryScore> = Default::default();
    let mut saw_any = false;

    for result in results {
        let Some(scores) = result.get("category_scores").and_then(Value::as_object) else {
            continue;
        };
        let flags = result.get("categories").and_then(Value::as_object);
        for (category, score) in scores {
            let Some(score) = score.as_f64() else { continue };
            saw_any = true;
            let violated = flags.and_then(|f| f.get(category)).and_then(Value::as_bool);
            // Batched inputs: keep the worst score per category, since
            // one violating item is enough to characterise the case.
            let entry = best.entry(category.clone()).or_insert(CategoryScore {
                category: category.clone(),
                score,
                violated,
            });
            if score > entry.score {
                entry.score = score;
                entry.violated = violated;
            }
        }
    }
    saw_any.then(|| best.into_values().collect())
}

/// `{"guardrails":[{"<guard>":{"categories":{"sexual":{"score":..,"violated":..}}}}]}`
fn parse_guardrails_shape(value: &Value) -> Option<Vec<CategoryScore>> {
    let guardrails = value.get("guardrails")?.as_array()?;
    let mut best: std::collections::BTreeMap<String, CategoryScore> = Default::default();
    let mut saw_any = false;

    for guardrail in guardrails {
        let Some(guards) = guardrail.as_object() else { continue };
        for guard in guards.values() {
            let Some(categories) = guard.get("categories").and_then(Value::as_object) else {
                continue;
            };
            for (category, detail) in categories {
                let Some(score) = detail.get("score").and_then(Value::as_f64) else {
                    continue;
                };
                saw_any = true;
                let violated = detail.get("violated").and_then(Value::as_bool);
                let entry = best.entry(category.clone()).or_insert(CategoryScore {
                    category: category.clone(),
                    score,
                    violated,
                });
                if score > entry.score {
                    entry.score = score;
                    entry.violated = violated;
                }
            }
        }
    }
    saw_any.then(|| best.into_values().collect())
}

/// Assess a case and, in autonomous mode, act on the result.
///
/// A recommended dismissal is applied at once — a dismissal is not a
/// sanction and making someone wait for one helps nobody. A
/// recommended ban is *not* applied here unless the response window
/// has already closed; it stays recorded, and the sweep applies it
/// when the accused's time to answer runs out.
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

    let assessment = match triage.assess(state, &case, now).await {
        Ok(assessment) => assessment,
        Err(e) => {
            // The case is untouched and still open. It will be retried
            // by the sweep, and failing that it hits its decision
            // deadline and is dismissed by default — an authority whose
            // classifier is down does not get to hold anyone.
            tracing::error!(%case_id, error = %e, "triage failed; case left open");
            return;
        }
    };

    if config.mode != TriageMode::Autonomous {
        return;
    }

    match Recommendation::parse(&assessment.recommendation) {
        Recommendation::Dismiss => {
            apply_automated(state, case_id, Disposition::Dismiss, &assessment, now).await;
        }
        Recommendation::Ban => {
            apply_automated(state, case_id, Disposition::Ban, &assessment, now).await;
        }
        Recommendation::Inconclusive => {
            tracing::info!(%case_id, "triage inconclusive; leaving the case open");
        }
    }
}

/// Re-attempt a ban the classifier recommended earlier and that was
/// deferred because the response window was still running.
pub async fn apply_deferred_ban(state: &AppState, case_id: &str, now: OffsetDateTime) {
    let Some(config) = state.config.triage.as_ref() else { return };
    if config.mode != TriageMode::Autonomous {
        return;
    }
    let Ok(Some((raw, applied))) = state.store.assessment(case_id) else { return };
    if applied {
        return;
    }
    let Ok(assessment) = serde_json::from_slice::<Assessment>(&raw) else { return };
    if Recommendation::parse(&assessment.recommendation) != Recommendation::Ban {
        return;
    }
    apply_automated(state, case_id, Disposition::Ban, &assessment, now).await;
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
        _ => format!(
            "automated triage: {} at {:.3}",
            assessment.recommendation, assessment.relevant_score
        ),
    };

    match decisions::apply(state, case_id, disposition, &reasoning, Decider::Automated, now).await {
        Ok(issued) => {
            let _ = state.store.mark_assessment_applied(case_id);
            tracing::info!(%case_id, verdict_ref = %issued.verdict_ref, "automated decision applied");
        }
        Err(Error::CaseState(reason)) => {
            // Most often: the response window is still running. Not a
            // failure — the sweep will come back to it.
            tracing::info!(%case_id, %reason, "automated decision deferred");
        }
        Err(e) => tracing::error!(%case_id, error = %e, "automated decision failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_results_shape() {
        let value: Value = serde_json::from_str(
            r#"{"id":"mod-1","model":"m","results":[{"categories":{"sexual":true},
                 "category_scores":{"sexual":0.91,"financial":0.02}}]}"#,
        )
        .unwrap();
        let scores = parse_scores(&value).unwrap();
        let sexual = scores.iter().find(|s| s.category == "sexual").unwrap();
        assert!((sexual.score - 0.91).abs() < 1e-9);
        assert_eq!(sexual.violated, Some(true));
    }

    #[test]
    fn parses_the_guardrails_shape() {
        let value: Value = serde_json::from_str(
            r#"{"guardrails":[{"moderation_llm_v2":{"categories":{
                 "sexual":{"score":0.03,"violated":false},
                 "selfharm":{"score":0.87,"violated":true}}}}]}"#,
        )
        .unwrap();
        let scores = parse_scores(&value).unwrap();
        let selfharm = scores.iter().find(|s| s.category == "selfharm").unwrap();
        assert!((selfharm.score - 0.87).abs() < 1e-9);
        assert_eq!(selfharm.violated, Some(true));
    }

    /// Batched inputs: one violating item characterises the case, so
    /// the worst score per category wins.
    #[test]
    fn keeps_the_worst_score_across_batched_inputs() {
        let value: Value = serde_json::from_str(
            r#"{"results":[{"category_scores":{"sexual":0.10}},
                           {"category_scores":{"sexual":0.95}}]}"#,
        )
        .unwrap();
        let scores = parse_scores(&value).unwrap();
        assert!((scores[0].score - 0.95).abs() < 1e-9);
    }

    /// The failure that would matter most: an unrecognised response
    /// must not normalize to "no categories", which downstream reads
    /// as a score of zero and therefore as an acquittal.
    #[test]
    fn an_unrecognised_response_yields_no_scores_rather_than_empty_ones() {
        for body in [
            r#"{"unexpected":"shape"}"#,
            r#"{"results":[]}"#,
            r#"{"results":[{"category_scores":{}}]}"#,
            r#"{"guardrails":[]}"#,
            r#"{}"#,
        ] {
            let value: Value = serde_json::from_str(body).unwrap();
            assert!(parse_scores(&value).is_none(), "{body}");
        }
    }

    #[test]
    fn non_numeric_scores_are_ignored_rather_than_defaulted() {
        let value: Value =
            serde_json::from_str(r#"{"results":[{"category_scores":{"sexual":"high"}}]}"#).unwrap();
        assert!(parse_scores(&value).is_none());
    }

    // ─── Recommendation policy ───────────────────────────────────────

    use crate::config::{TriageConfig, TriageMode};

    fn config(map: &[(&str, &[&str])]) -> TriageConfig {
        TriageConfig {
            mode: TriageMode::Autonomous,
            url: "http://moderation-model:8000/v1/moderations".into(),
            model: "test".into(),
            api_key: None,
            ban_threshold: 0.9,
            dismiss_threshold: 0.2,
            category_map: map
                .iter()
                .map(|(class, cats)| {
                    (class.to_string(), cats.iter().map(|c| c.to_string()).collect())
                })
                .collect(),
            timeout_secs: 5,
        }
    }

    /// The scoring rule, isolated: only categories mapped to the class
    /// count, and the band between the thresholds decides nothing.
    fn recommend(config: &TriageConfig, class_id: &str, scores: &[(&str, f64)]) -> Recommendation {
        let relevant: Vec<String> = config.category_map.get(class_id).cloned().unwrap_or_default();
        let relevant_score = scores
            .iter()
            .filter(|(c, _)| relevant.iter().any(|r| r == c))
            .map(|(_, s)| *s)
            .fold(0.0_f64, f64::max);
        if relevant.is_empty() {
            Recommendation::Inconclusive
        } else if relevant_score >= config.ban_threshold {
            Recommendation::Ban
        } else if relevant_score <= config.dismiss_threshold {
            Recommendation::Dismiss
        } else {
            Recommendation::Inconclusive
        }
    }

    #[test]
    fn only_categories_mapped_to_the_class_count() {
        let config = config(&[("unsolicited-pornography", &["sexual"])]);

        // A high score in an unmapped category is irrelevant: the user
        // consented to be judged on this class, not on everything the
        // model happens to detect.
        assert_eq!(
            recommend(&config, "unsolicited-pornography", &[("financial", 0.99), ("sexual", 0.05)]),
            Recommendation::Dismiss
        );
        assert_eq!(
            recommend(&config, "unsolicited-pornography", &[("sexual", 0.97)]),
            Recommendation::Ban
        );
    }

    #[test]
    fn the_band_between_thresholds_decides_nothing() {
        let config = config(&[("unsolicited-pornography", &["sexual"])]);
        assert_eq!(
            recommend(&config, "unsolicited-pornography", &[("sexual", 0.5)]),
            Recommendation::Inconclusive
        );
    }

    /// A class the operator never mapped cannot be scored. Inventing a
    /// number for it would be judging terms the mapping never covered.
    #[test]
    fn an_unmapped_class_is_inconclusive_rather_than_dismissed() {
        let config = config(&[("csam", &["sexual"])]);
        assert_eq!(
            recommend(&config, "credible-violence", &[("violence_and_threats", 0.99)]),
            Recommendation::Inconclusive
        );
    }

    #[test]
    fn thresholds_are_inclusive_at_both_ends() {
        let config = config(&[("c", &["x"])]);
        assert_eq!(recommend(&config, "c", &[("x", 0.9)]), Recommendation::Ban);
        assert_eq!(recommend(&config, "c", &[("x", 0.2)]), Recommendation::Dismiss);
    }
}
