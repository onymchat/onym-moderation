//! The moderator's web panel.
//!
//! Its queue is **appeals**, not cases. Triage decides in the first
//! instance; a human reads the file when someone says the machine got
//! it wrong. That mirrors where the contract puts human judgment —
//! notice, response, and then an appeal path that can reverse — rather
//! than putting a person in front of every report.
//!
//! Everything is server-rendered. This screen shows disclosed evidence
//! from real cases, so it is behind a session cookie and deliberately
//! has no client-side dependencies to pull that content into.

use std::sync::Arc;

use axum::extract::{Form, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use time::OffsetDateTime;

use crate::decisions::{self, Decider, Disposition};
use crate::error::Error;
use crate::state::AppState;
use crate::store::CaseRecord;
use crate::util;

const SESSION_COOKIE: &str = "onym_moderation_session";
const SESSION_HOURS: i64 = 8;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/admin", get(index))
        .route("/admin/login", post(login))
        .route("/admin/logout", post(logout))
        .route("/admin/cases/:case_id", get(case_detail))
        .route("/admin/cases/:case_id/review", post(review))
        .with_state(state)
}

// ─── Session ─────────────────────────────────────────────────────────

fn session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE)
        .map(|(_, value)| value.to_string())
}

fn authenticated(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(token) = session_cookie(headers) else { return false };
    let now = util::format_timestamp(OffsetDateTime::now_utc());
    state.store.admin_session_valid(&token, &now).unwrap_or(false)
}

#[derive(Deserialize)]
struct LoginForm {
    token: String,
}

async fn login(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginForm>,
) -> Result<Response, Error> {
    let Some(expected) = state.config.admin_token.as_deref() else {
        return Err(Error::SignatureInvalid(
            "AUTHORITY_ADMIN_TOKEN is not configured; the panel is closed".into(),
        ));
    };
    if !constant_time_eq(form.token.as_bytes(), expected.as_bytes()) {
        // No detail about which part was wrong.
        return Ok((StatusCode::UNAUTHORIZED, Html(login_page(true))).into_response());
    }

    let session = util::sha256_hex(uuid::Uuid::new_v4().as_bytes());
    let now = OffsetDateTime::now_utc();
    state.store.create_admin_session(
        &session,
        &util::format_timestamp(now),
        &util::format_timestamp(now + time::Duration::hours(SESSION_HOURS)),
    )?;

    // HttpOnly so script cannot read it, SameSite=Strict so another
    // site cannot ride it, Secure because the panel is served over
    // TLS in every deployment that matters.
    let cookie = format!(
        "{SESSION_COOKIE}={session}; HttpOnly; SameSite=Strict; Secure; Path=/admin; Max-Age={}",
        SESSION_HOURS * 3600
    );
    Ok(([(header::SET_COOKIE, cookie)], Redirect::to("/admin")).into_response())
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, Error> {
    if let Some(token) = session_cookie(&headers) {
        state.store.destroy_admin_session(&token)?;
    }
    let cleared = format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Secure; Path=/admin; Max-Age=0");
    Ok(([(header::SET_COOKIE, cleared)], Redirect::to("/admin")).into_response())
}

// ─── Queue ───────────────────────────────────────────────────────────

async fn index(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, Error> {
    if !authenticated(&state, &headers) {
        return Ok(Html(login_page(false)).into_response());
    }

    let appeals = state.store.cases_awaiting_appeal_review()?;
    let recent = state.store.recent_cases(50)?;

    let mut body = String::new();
    body.push_str(&format!(
        "<h1>{}</h1><p class=sub>Appeals are the queue. Triage decides in the first instance; \
         you read the file when someone says it got it wrong.</p>",
        escape(&state.config.manifest.component_id)
    ));

    body.push_str(&format!("<h2>Appeals awaiting review ({})</h2>", appeals.len()));
    if appeals.is_empty() {
        body.push_str("<p class=empty>Nothing waiting. </p>");
    } else {
        body.push_str(&case_table(&appeals));
    }

    body.push_str("<h2>Recent cases</h2>");
    body.push_str(&case_table(&recent));
    body.push_str(
        "<form method=post action=/admin/logout><button class=secondary>Sign out</button></form>",
    );

    Ok(Html(page("Moderation queue", &body)).into_response())
}

fn case_table(cases: &[CaseRecord]) -> String {
    let mut out = String::from(
        "<table><tr><th>Case</th><th>Class</th><th>Stage</th><th>Disposition</th>\
         <th>Appeal</th><th>Opened</th></tr>",
    );
    for case in cases {
        out.push_str(&format!(
            "<tr><td><a href=\"/admin/cases/{id}\">{short}</a></td><td>{class}</td>\
             <td>{stage}</td><td>{disposition}</td><td>{appeal}</td><td>{opened}</td></tr>",
            id = escape(&case.case_id),
            short = escape(case.case_id.get(..13).unwrap_or(&case.case_id)),
            class = escape(&case.class_id),
            stage = escape(&case.stage),
            disposition = escape(case.disposition.as_deref().unwrap_or("—")),
            appeal = escape(&case.appeal_state),
            opened = escape(&case.opened_at),
        ));
    }
    out.push_str("</table>");
    out
}

// ─── Case detail ─────────────────────────────────────────────────────

async fn case_detail(
    State(state): State<Arc<AppState>>,
    Path(case_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    if !authenticated(&state, &headers) {
        return Ok(Html(login_page(false)).into_response());
    }
    let case = state
        .store
        .case(&case_id)?
        .ok_or_else(|| Error::NotFound(format!("case {case_id}")))?;

    let mut body = format!("<h1>Case {}</h1>", escape(&case.case_id));
    body.push_str(&format!(
        "<table class=facts>\
         <tr><th>Class</th><td>{class}</td></tr>\
         <tr><th>Accused</th><td class=mono>{accused}</td></tr>\
         <tr><th>Stage</th><td>{stage}</td></tr>\
         <tr><th>Disposition</th><td>{disposition}</td></tr>\
         <tr><th>Responded</th><td>{responded}</td></tr>\
         <tr><th>Response deadline</th><td>{response}</td></tr>\
         <tr><th>Decision deadline</th><td>{decision}</td></tr>\
         <tr><th>Appeal</th><td>{appeal}</td></tr></table>",
        class = escape(&case.class_id),
        accused = escape(&case.accused),
        stage = escape(&case.stage),
        disposition = escape(case.disposition.as_deref().unwrap_or("—")),
        responded = if case.responded { "yes" } else { "no" },
        response = escape(&case.response_deadline),
        decision = escape(&case.decision_deadline),
        appeal = escape(&case.appeal_state),
    ));
    // The reporter's identity is deliberately absent: it is visible to
    // the authority, never to the accused, and a reviewer does not need
    // it to weigh the evidence (§5.4 constraint 4).

    body.push_str(&assessment_section(&state, &case_id));

    body.push_str("<h2>Disclosed evidence</h2>");
    let evidence = state.store.evidence_for_case(&case_id)?;
    if evidence.is_empty() {
        body.push_str("<p class=empty>No stored evidence.</p>");
    } else {
        for item in evidence {
            body.push_str(&format!("<pre class=evidence>{}</pre>", escape(&item)));
        }
    }

    body.push_str("<h2>History</h2><table><tr><th>At</th><th>Event</th><th>Detail</th></tr>");
    for (at, kind, detail) in state.store.events(&case_id)? {
        body.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape(&at),
            escape(&kind),
            escape(&detail)
        ));
    }
    body.push_str("</table>");

    body.push_str(&review_form(&case));
    body.push_str("<p><a href=/admin>← queue</a></p>");

    Ok(Html(page(&format!("Case {}", case.case_id), &body)).into_response())
}

fn assessment_section(state: &AppState, case_id: &str) -> String {
    let Ok(Some((raw, applied))) = state.store.assessment(case_id) else {
        return "<h2>Automated assessment</h2><p class=empty>None — this case was not \
                classified.</p>"
            .to_string();
    };
    let Ok(assessment) = serde_json::from_slice::<serde_json::Value>(&raw) else {
        return "<h2>Automated assessment</h2><p class=empty>Stored assessment is \
                unreadable.</p>"
            .to_string();
    };

    let mut out = String::from("<h2>Automated assessment</h2>");
    out.push_str(&format!(
        "<p>Model <span class=mono>{model}</span> recommended \
         <strong>{recommendation}</strong> at {score:.3} \
         (applied: {applied}). Content address \
         <span class=mono>sha256:{hash}</span> — this is what the verdict's reasoning \
         points at.</p>",
        model = escape(assessment["model"].as_str().unwrap_or("?")),
        recommendation = escape(assessment["recommendation"].as_str().unwrap_or("?")),
        score = assessment["relevantScore"].as_f64().unwrap_or(0.0),
        applied = if applied { "yes" } else { "no" },
        hash = util::sha256_hex(&raw),
    ));

    if let Some(relevant) = assessment["relevantCategories"].as_array() {
        let names: Vec<String> = relevant
            .iter()
            .filter_map(|c| c.as_str())
            .map(escape)
            .collect();
        out.push_str(&format!(
            "<p class=sub>Judged on: {}</p>",
            if names.is_empty() { "—".to_string() } else { names.join(", ") }
        ));
    }

    out.push_str("<table><tr><th>Category</th><th>Score</th><th>Flagged</th></tr>");
    if let Some(categories) = assessment["categories"].as_array() {
        for category in categories {
            out.push_str(&format!(
                "<tr><td>{}</td><td>{:.3}</td><td>{}</td></tr>",
                escape(category["category"].as_str().unwrap_or("?")),
                category["score"].as_f64().unwrap_or(0.0),
                match category["violated"].as_bool() {
                    Some(true) => "yes",
                    Some(false) => "no",
                    None => "—",
                }
            ));
        }
    }
    out.push_str("</table>");
    out
}

fn review_form(case: &CaseRecord) -> String {
    // Reversal is only meaningful against a ban; upholding is only
    // meaningful while an appeal is pending.
    let can_reverse = case.disposition.as_deref() == Some("ban");
    let appeal_pending = case.appeal_state == "pending";

    let mut out = String::from("<h2>Review</h2>");
    if !appeal_pending && !can_reverse {
        out.push_str(
            "<p class=empty>No appeal is pending and there is no ban to reverse, so there is \
             nothing for a reviewer to do here.</p>",
        );
        return out;
    }

    out.push_str(&format!(
        "<form method=post action=\"/admin/cases/{id}/review\">\
         <label>Reasoning — a content address of your findings against the consented class \
         definition, not a sentence.<br>\
         <input name=reasoning size=70 placeholder=\"sha256:… or https://…\" required></label><br>",
        id = escape(&case.case_id)
    ));
    if appeal_pending {
        out.push_str(
            "<button name=outcome value=uphold class=secondary>Uphold the verdict</button> ",
        );
    }
    if can_reverse {
        out.push_str("<button name=outcome value=reverse>Reverse — clears the marks</button>");
    }
    out.push_str("</form>");
    out
}

#[derive(Deserialize)]
struct ReviewForm {
    outcome: String,
    reasoning: String,
}

/// The human's decision on an appeal.
///
/// Upholding issues no verdict: the one in force already says what it
/// says, and re-signing it would only muddy the record. Reversing
/// issues a fresh verdict that clears the marks, which is the only
/// conforming way to undo one (§12).
async fn review(
    State(state): State<Arc<AppState>>,
    Path(case_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<ReviewForm>,
) -> Result<Response, Error> {
    if !authenticated(&state, &headers) {
        return Ok(Html(login_page(false)).into_response());
    }
    if form.reasoning.trim().is_empty() {
        return Err(Error::BadRequest("reasoning is required".into()));
    }

    state
        .store
        .case(&case_id)?
        .ok_or_else(|| Error::NotFound(format!("case {case_id}")))?;
    let now = OffsetDateTime::now_utc();
    let stamp = util::format_timestamp(now);

    match form.outcome.as_str() {
        "uphold" => {
            state.store.set_appeal_state(
                &case_id,
                "upheld",
                &stamp,
                "appeal_upheld",
                &form.reasoning,
            )?;
        }
        "reverse" => {
            // The reviewer saw the classifier's assessment on the way
            // here, so the decision is recorded as assisted rather than
            // as unaided human judgment.
            decisions::apply(
                &state,
                &case_id,
                Disposition::Reverse,
                &form.reasoning,
                Decider::HumanAssisted,
                now,
            )
            .await?;
            state.store.set_appeal_state(
                &case_id,
                "reversed",
                &stamp,
                "appeal_reversed",
                &form.reasoning,
            )?;
        }
        other => return Err(Error::BadRequest(format!("unknown outcome {other:?}"))),
    }

    Ok(Redirect::to(&format!("/admin/cases/{case_id}")).into_response())
}

// ─── Rendering ───────────────────────────────────────────────────────

/// Minimal escaping. Everything rendered here is attacker-supplied by
/// construction — the evidence *is* content someone else wrote — so no
/// value reaches the page without passing through this.
fn escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for character in raw.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(character),
        }
    }
    out
}

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8>\
         <meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>{title}</title><style>{STYLE}</style></head><body><main>{body}</main></body></html>",
        title = escape(title),
        body = body,
        STYLE = STYLE
    )
}

fn login_page(failed: bool) -> String {
    let error = if failed { "<p class=error>That token was not accepted.</p>" } else { "" };
    page(
        "Sign in",
        &format!(
            "<h1>Moderation panel</h1>\
             <p class=sub>This screen shows evidence disclosed inside cases. Do not open it \
             where it can be read over your shoulder.</p>{error}\
             <form method=post action=/admin/login>\
             <label>Moderator token<br><input name=token type=password size=48 required></label><br>\
             <button>Sign in</button></form>"
        ),
    )
}

const STYLE: &str = "
:root { color-scheme: light dark; }
body { font: 15px/1.5 -apple-system, system-ui, sans-serif; margin: 0; padding: 2rem 1rem; }
main { max-width: 60rem; margin: 0 auto; }
h1 { font-size: 1.5rem; margin-bottom: .25rem; }
h2 { font-size: 1.1rem; margin-top: 2rem; }
.sub { opacity: .7; }
.empty { opacity: .6; font-style: italic; }
.error { color: #c0392b; font-weight: 600; }
.mono, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85em; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0; }
th, td { text-align: left; padding: .4rem .5rem; border-bottom: 1px solid rgba(128,128,128,.3); }
th { font-weight: 600; opacity: .8; }
table.facts th { width: 12rem; }
pre.evidence { white-space: pre-wrap; word-break: break-word; padding: .75rem;
  background: rgba(128,128,128,.12); border-radius: 6px; }
input { padding: .4rem; margin: .25rem 0 .75rem; }
button { padding: .5rem .9rem; border-radius: 6px; border: 0; background: #c0392b; color: #fff;
  font-size: .95rem; cursor: pointer; }
button.secondary { background: rgba(128,128,128,.35); color: inherit; }
a { color: inherit; }
";

fn constant_time_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }
    lhs.iter().zip(rhs).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The panel renders evidence, which is by definition text a
    /// stranger wrote. Escaping is the only thing between that and the
    /// moderator's session.
    #[test]
    fn evidence_is_escaped_before_rendering() {
        let hostile = r#"<script>fetch('/admin/cases')</script>"#;
        let escaped = escape(hostile);
        assert!(!escaped.contains("<script>"));
        assert!(escaped.contains("&lt;script&gt;"));
    }

    #[test]
    fn escaping_covers_attribute_breakouts() {
        assert_eq!(escape(r#"" onmouseover="x"#), "&quot; onmouseover=&quot;x");
        assert_eq!(escape("' onfocus='x"), "&#39; onfocus=&#39;x");
        assert_eq!(escape("a & b"), "a &amp; b");
    }

    #[test]
    fn session_cookie_is_parsed_from_a_cookie_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "other=1; onym_moderation_session=abc123; another=2".parse().unwrap(),
        );
        assert_eq!(session_cookie(&headers).as_deref(), Some("abc123"));

        let empty = HeaderMap::new();
        assert_eq!(session_cookie(&empty), None);
    }
}
