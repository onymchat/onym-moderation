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
        return "<h2>Automated assessment</h2><p class=empty>None — this case has not been \
                assessed. A case is not shown to a model until its response window closes.</p>"
            .to_string();
    };
    let Ok(assessment) = serde_json::from_slice::<serde_json::Value>(&raw) else {
        return "<h2>Automated assessment</h2><p class=empty>Stored assessment is \
                unreadable.</p>"
            .to_string();
    };

    let field = |name: &str| escape(assessment[name].as_str().unwrap_or("?"));
    let mut out = String::from("<h2>Automated assessment</h2>");

    // Outcome first, then everything needed to check it. A reviewer on
    // appeal is deciding whether the machine was right, which means
    // they need what it was shown and what it actually said — not a
    // summary of either.
    out.push_str(&format!(
        "<p>Outcome <strong>{outcome}</strong> (applied: {applied}). Content address \
         <span class=mono>sha256:{hash}</span> — this is what the verdict's reasoning points \
         at.</p><p class=sub>{note}</p>",
        outcome = field("outcome"),
        applied = if applied { "yes" } else { "no" },
        hash = util::sha256_hex(&raw),
        note = field("note"),
    ));

    if let Some(score) = assessment["score"].as_f64() {
        out.push_str(&format!("<p>Violation score <strong>{score:.4}</strong></p>"));
    } else {
        // Said explicitly, because the absence is deliberate: a
        // label-producing model has no calibrated score, and inventing
        // one would put a fabricated number in a case file where it
        // would read as evidence.
        out.push_str(
            "<p class=sub>This profile produces a label, not a calibrated score. No confidence \
             number is recorded because there is none to record.</p>",
        );
    }

    if let Some(labels) = assessment["labels"].as_array() {
        let names: Vec<String> = labels.iter().filter_map(|l| l.as_str()).map(escape).collect();
        if !names.is_empty() {
            out.push_str(&format!("<p class=sub>Labels returned: {}</p>", names.join(", ")));
        }
    }

    out.push_str("<table>");
    for (label, value) in [
        ("Profile", field("profileId")),
        ("Model", field("repository")),
        ("Revision", field("revision")),
        ("Profile digest", field("profileDigest")),
        ("Policy digest", field("policyDigest")),
        ("Class", field("classId")),
        ("Case-document digest", field("inputDigest")),
        ("Assessed at", field("assessedAt")),
    ] {
        out.push_str(&format!("<tr><th>{label}</th><td class=mono>{value}</td></tr>"));
    }
    out.push_str(&format!(
        "<tr><th>Document contents</th><td>{} evidence item(s), {} response(s)</td></tr>",
        assessment["evidenceItems"].as_u64().unwrap_or(0),
        assessment["responseItems"].as_u64().unwrap_or(0),
    ));
    out.push_str("</table>");

    // The model's own words, escaped. This is the thing an appeal is
    // actually about.
    out.push_str(&format!(
        "<h3>Final model output</h3><pre class=mono>{}</pre>",
        escape(assessment["rawOutput"].as_str().unwrap_or(""))
    ));

    // And the document it read. For the native-taxonomy profiles the
    // terms promise a human applies the *narrower* canonical rule on
    // appeal — which cannot be done from a digest. The rule itself is
    // rendered alongside it for the same reason.
    match state.store.assessed_document(case_id) {
        Ok(Some(document)) => {
            out.push_str(&format!(
                "<h3>The case document the model read</h3><pre class=mono>{}</pre>",
                escape(&document)
            ));
        }
        _ => out.push_str(
            "<h3>The case document the model read</h3><p class=empty>Not on file — this \
             assessment predates the document being stored.</p>",
        ),
    }

    if let Some(rule) = assessment["classId"].as_str().and_then(crate::policy::rule_for_class) {
        out.push_str(&format!(
            "<h3>The canonical rule to apply</h3><pre class=mono>{}</pre>\
             <p class=sub>Where the profile uses the model's own taxonomy, its terms promise \
             that a human applies <em>this</em> rule on appeal, and reverses when its required \
             elements are not proved.</p>",
            escape(&rule.as_prompt_text())
        ));
    }

    out
}

fn review_form(case: &CaseRecord) -> String {
    // Two claims, two controls. An appeal says the verdict was wrong; a
    // new-holder claim says the device changed hands and the mark is
    // punishing someone the case was never about. They are filed by
    // different people — the second by anyone who knows the case id —
    // and one pair of buttons could only ever answer one of them,
    // which left the other pending forever with the page describing
    // the wrong claim.
    let can_reverse = case.disposition.as_deref() == Some("ban");
    let appeal_pending = case.appeal_state == "pending";
    let claim_pending = case.new_holder_state == "pending";

    let mut out = String::from("<h2>Review</h2>");
    if !appeal_pending && !claim_pending && !can_reverse {
        out.push_str(
            "<p class=empty>Nothing is pending and there is no ban to reverse, so there is \
             nothing for a reviewer to do here.</p>",
        );
        return out;
    }

    let reasoning_field = "<label>Reasoning — a content address of your findings against the \
         consented class definition, not a sentence.<br>\
         <input name=reasoning size=70 placeholder=\"sha256:… or https://…\" required></label><br>";

    if appeal_pending {
        out.push_str(&format!(
            "<h3>Appeal</h3>\
             <p class=sub>The accused says this verdict was wrong.</p>\
             <form method=post action=\"/admin/cases/{id}/review\">\
             <input type=hidden name=subject value=appeal>{reasoning_field}\
             <button name=outcome value=uphold class=secondary>Uphold the verdict</button> ",
            id = escape(&case.case_id)
        ));
        if can_reverse {
            out.push_str("<button name=outcome value=reverse>Reverse — clears the marks</button>");
        }
        out.push_str("</form>");
    }

    if claim_pending {
        out.push_str(&format!(
            "<h3>New-holder claim</h3>\
             <p class=sub><strong>This is not an appeal.</strong> The claim is not that the \
             verdict was wrong — it is that this device has a different owner now, and the mark \
             is punishing them. Granting it clears the marks; refusing leaves them in force \
             against hardware whose holder may have changed. Anyone who knows this case id can \
             file one, so weigh it on what it shows.</p>\
             <form method=post action=\"/admin/cases/{id}/review\">\
             <input type=hidden name=subject value=new-holder>{reasoning_field}\
             <button name=outcome value=uphold class=secondary>Refuse the claim — marks \
             stay</button> ",
            id = escape(&case.case_id)
        ));
        if can_reverse {
            out.push_str("<button name=outcome value=reverse>Grant it — clears the marks</button>");
        }
        out.push_str("</form>");
    }

    // A ban with nothing pending: the authority correcting itself.
    if can_reverse && !appeal_pending && !claim_pending {
        out.push_str(&format!(
            "<h3>Correct this verdict</h3>\
             <p class=sub>Nothing is pending. Reversing here is this authority correcting its \
             own error, and is recorded as that rather than as an appeal outcome.</p>\
             <form method=post action=\"/admin/cases/{id}/review\">\
             <input type=hidden name=subject value=none>{reasoning_field}\
             <button name=outcome value=reverse>Reverse — clears the marks</button></form>",
            id = escape(&case.case_id)
        ));
    }

    out
}

#[derive(Deserialize)]
struct ReviewForm {
    outcome: String,
    reasoning: String,
    /// Which claim this answers: `appeal`, `new-holder`, or `none` for
    /// the authority correcting a verdict nobody contested. The page
    /// renders one form per pending claim, because collapsing them
    /// meant answering one left the other pending forever.
    #[serde(default)]
    subject: String,
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

    let now = OffsetDateTime::now_utc();
    let stamp = util::format_timestamp(now);

    // The buttons are hidden when they do not apply, but a form POST
    // is reachable without them. Without these, a moderator could
    // stamp "appeal upheld" on a case nobody appealed — a record of a
    // review that never happened, in the one place a user is supposed
    // to be able to check that it did.
    let case = state
        .store
        .case(&case_id)?
        .ok_or_else(|| Error::NotFound(format!("case {case_id}")))?;

    // Which claim is being answered comes from the form, not from
    // whichever happens to be pending. A case can carry both at once —
    // the new-holder path is unauthenticated, so a stranger can add one
    // beside the accused's appeal — and inferring the subject meant
    // every review answered the same one and left the other queued.
    let subject = match form.subject.as_str() {
        "appeal" => "appeal",
        "new-holder" => "new-holder",
        "" => {
            // Older form posts carry no subject. Answer the appeal if
            // one is pending, else the claim; refuse when both are, so
            // an ambiguous request cannot silently pick for a reviewer.
            match (case.appeal_state == "pending", case.new_holder_state == "pending") {
                (true, true) => {
                    return Err(Error::BadRequest(
                        "this case has both an appeal and a new-holder claim pending; say which \
                         one this answers"
                            .into(),
                    ))
                }
                (true, false) => "appeal",
                (false, true) => "new-holder",
                (false, false) => "none",
            }
        }
        other => return Err(Error::BadRequest(format!("unknown review subject {other:?}"))),
    };

    if form.outcome == "uphold" {
        let pending = match subject {
            "appeal" => case.appeal_state == "pending",
            "new-holder" => case.new_holder_state == "pending",
            _ => false,
        };
        if !pending {
            return Err(Error::CaseState(format!(
                "there is no {subject} pending on this case to decide"
            )));
        }
    }
    if form.outcome == "reverse" && case.disposition.as_deref() != Some("ban") {
        return Err(Error::CaseState("only a ban can be reversed".into()));
    }

    match form.outcome.as_str() {
        "uphold" => {
            // The case log has to say which kind of review happened. A
            // device-changed-hands claim recorded as "appeal upheld"
            // is a record of a review nobody asked for.
            if subject == "new-holder" {
                state.store.set_new_holder_state(
                    &case_id,
                    "refused",
                    &stamp,
                    "new_holder_claim_refused",
                    &form.reasoning,
                )?;
            } else {
                state.store.set_appeal_state(
                    &case_id,
                    "upheld",
                    &stamp,
                    "appeal_upheld",
                    &form.reasoning,
                )?;
            }
        }
        "reverse" => {
            // The reviewer saw the classifier's assessment on the way
            // here, so the decision is recorded as assisted rather than
            // as unaided human judgment.
            // `apply` resolves whatever was pending and records the
            // review in the same transaction — the panel does not get
            // to decide what kind of review this was, because the JSON
            // API reaches the same code and must reach the same
            // answer.
            decisions::apply(
                &state,
                &case_id,
                Disposition::Reverse,
                &form.reasoning,
                // Assisted only if there was something to assist with.
                // Hardcoding it meant a reversal on a case triage never
                // touched — or a deployment with triage off entirely —
                // was logged as reached with a classifier's help that
                // never existed, in the record this distinction exists
                // for.
                if state.store.assessment(&case_id)?.is_some() {
                    Decider::HumanAssisted
                } else {
                    Decider::Human
                },
                now,
            )
            .await?;
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

    use crate::store::{CaseRecord, Store};

    /// An authenticated moderator's headers.
    fn signed_in(state: &AppState) -> HeaderMap {
        let now = OffsetDateTime::now_utc();
        state
            .store
            .create_admin_session(
                "session-token",
                &util::format_timestamp(now),
                &util::format_timestamp(now + time::Duration::hours(1)),
            )
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, format!("{SESSION_COOKIE}=session-token").parse().unwrap());
        headers
    }

    fn reviewable_case(disposition: Option<&str>, appeal_state: &str) -> CaseRecord {
        reviewable_case_with(disposition, appeal_state, "none")
    }

    fn reviewable_case_with(
        disposition: Option<&str>,
        appeal_state: &str,
        new_holder_state: &str,
    ) -> CaseRecord {
        CaseRecord {
            case_id: "c1".into(),
            accused: "onym:key:acc".into(),
            reporter: "onym:key:rep".into(),
            class_id: "csam".into(),
            mandate_ref: "m1".into(),
            device_binding: "d1".into(),
            stage: "decided".into(),
            opened_at: "2026-08-01T00:00:00Z".into(),
            response_deadline: "2026-08-04T00:00:00Z".into(),
            decision_deadline: "2026-08-08T00:00:00Z".into(),
            responded: false,
            disposition: disposition.map(str::to_string),
            appeal_deadline: None,
            appeal_state: appeal_state.into(),
            new_holder_state: new_holder_state.into(),
        }
    }

    /// The buttons are hidden when they do not apply, but the POST is
    /// reachable without them. Upholding an appeal nobody filed writes
    /// a record of a review that never happened — in the one place a
    /// user is supposed to be able to check that it did.
    #[tokio::test]
    async fn upholding_requires_a_pending_appeal() {
        let state = Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&reviewable_case(Some("ban"), "none")).unwrap();

        let result = review(
            State(state.clone()),
            Path("c1".to_string()),
            signed_in(&state),
            Form(ReviewForm { outcome: "uphold".into(), reasoning: "hash:reviewed".into(), subject: String::new() }),
        )
        .await;

        assert!(matches!(result, Err(Error::CaseState(_))), "no appeal is pending");
        assert_eq!(state.store.case("c1").unwrap().unwrap().appeal_state, "none");
    }

    /// And reversing needs a ban to reverse.
    #[tokio::test]
    async fn reversing_requires_a_ban() {
        let state = Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&reviewable_case(Some("dismiss"), "pending")).unwrap();

        let result = review(
            State(state.clone()),
            Path("c1".to_string()),
            signed_in(&state),
            Form(ReviewForm { outcome: "reverse".into(), reasoning: "hash:reviewed".into(), subject: String::new() }),
        )
        .await;

        assert!(matches!(result, Err(Error::CaseState(_))), "a dismissal is not a ban");
    }

    /// A pending appeal can be upheld, which is the path these guards
    /// must not have broken.
    #[tokio::test]
    async fn a_pending_appeal_can_be_upheld() {
        let state = Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&reviewable_case(Some("ban"), "pending")).unwrap();

        review(
            State(state.clone()),
            Path("c1".to_string()),
            signed_in(&state),
            Form(ReviewForm { outcome: "uphold".into(), reasoning: "hash:reviewed".into(), subject: String::new() }),
        )
        .await
        .unwrap();

        assert_eq!(state.store.case("c1").unwrap().unwrap().appeal_state, "upheld");
    }


    /// A new-holder claim reaching the panel must be decided as one.
    /// Recorded as "appeal upheld", the case log would claim a review
    /// nobody asked for.
    #[tokio::test]
    async fn a_new_holder_claim_is_refused_as_itself_not_as_an_appeal() {
        let state = Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&reviewable_case_with(Some("ban"), "none", "pending")).unwrap();

        review(
            State(state.clone()),
            Path("c1".to_string()),
            signed_in(&state),
            Form(ReviewForm { outcome: "uphold".into(), reasoning: "hash:reviewed".into(), subject: String::new() }),
        )
        .await
        .unwrap();

        let case = state.store.case("c1").unwrap().unwrap();
        assert_eq!(case.new_holder_state, "refused");
        assert_eq!(case.appeal_state, "none", "no appeal was touched");
        let events = state.store.events("c1").unwrap();
        assert!(events.iter().any(|(_, kind, _)| kind == "new_holder_claim_refused"));
        assert!(
            !events.iter().any(|(_, kind, _)| kind == "appeal_upheld"),
            "the log must not claim an appeal was upheld"
        );
    }

    /// Reversing on appeal moves the case and the appeal together.
    /// Separately, a failure between them left the case reversed while
    /// its appeal still read pending — back in the queue, with the
    /// review that decided it missing from the file.
    #[tokio::test]
    async fn a_reversal_and_its_appeal_state_move_together() {
        let state = Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&reviewable_case(Some("ban"), "pending")).unwrap();

        review(
            State(state.clone()),
            Path("c1".to_string()),
            signed_in(&state),
            Form(ReviewForm { outcome: "reverse".into(), reasoning: "hash:reviewed".into(), subject: String::new() }),
        )
        .await
        .unwrap();

        let case = state.store.case("c1").unwrap().unwrap();
        assert_eq!(case.disposition.as_deref(), Some("reversed"));
        assert_eq!(case.appeal_state, "reversed");
        assert!(
            state.store.cases_awaiting_appeal_review().unwrap().is_empty(),
            "a reviewed appeal leaves the queue"
        );
    }


    /// Both claims at once — the state an *unauthenticated* new-holder
    /// filing can create beside the accused's appeal. One pair of
    /// buttons could only answer one of them, so every uphold recorded
    /// a claim refusal and left the appeal pending forever, with the
    /// page describing the wrong claim.
    #[tokio::test]
    async fn each_pending_claim_is_answered_separately() {
        let state = Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&reviewable_case_with(Some("ban"), "pending", "pending")).unwrap();

        // Answer the *appeal* first, with the claim still pending —
        // the order that exposed the collapse. Upholding used to
        // branch on "is a claim pending", so this recorded a claim
        // refusal and left the appeal queued forever.
        review(
            State(state.clone()),
            Path("c1".to_string()),
            signed_in(&state),
            Form(ReviewForm {
                outcome: "uphold".into(),
                reasoning: "hash:appeal".into(),
                subject: "appeal".into(),
            }),
        )
        .await
        .unwrap();
        let case = state.store.case("c1").unwrap().unwrap();
        assert_eq!(case.appeal_state, "upheld", "the appeal was what was answered");
        assert_eq!(case.new_holder_state, "pending", "the claim is still owed an answer");
        let events = state.store.events("c1").unwrap();
        assert!(events.iter().any(|(_, kind, _)| kind == "appeal_upheld"));
        assert!(
            !events.iter().any(|(_, kind, _)| kind == "new_holder_claim_refused"),
            "answering the appeal must not record a claim refusal"
        );

        // Then the claim, separately.
        review(
            State(state.clone()),
            Path("c1".to_string()),
            signed_in(&state),
            Form(ReviewForm {
                outcome: "uphold".into(),
                reasoning: "hash:claim".into(),
                subject: "new-holder".into(),
            }),
        )
        .await
        .unwrap();
        let case = state.store.case("c1").unwrap().unwrap();
        assert_eq!(case.new_holder_state, "refused");
        assert!(
            state.store.cases_awaiting_appeal_review().unwrap().is_empty(),
            "with both answered the case leaves the queue"
        );
    }

    /// A form post that does not say which claim it answers, on a case
    /// carrying both, must not pick one silently.
    #[tokio::test]
    async fn an_ambiguous_review_is_refused_rather_than_guessed() {
        let state = Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&reviewable_case_with(Some("ban"), "pending", "pending")).unwrap();

        let result = review(
            State(state.clone()),
            Path("c1".to_string()),
            signed_in(&state),
            Form(ReviewForm {
                outcome: "uphold".into(),
                reasoning: "hash:r".into(),
                subject: String::new(),
            }),
        )
        .await;
        assert!(matches!(result, Err(Error::BadRequest(_))), "{result:?}");
        let case = state.store.case("c1").unwrap().unwrap();
        assert_eq!(case.appeal_state, "pending");
        assert_eq!(case.new_holder_state, "pending");
    }

    /// The page offers a control per pending claim, and says which is
    /// which — a reviewer answering a claim should not be reading a
    /// heading about an appeal.
    #[test]
    fn the_page_offers_one_control_per_pending_claim() {
        let both = review_form(&reviewable_case_with(Some("ban"), "pending", "pending"));
        assert_eq!(both.matches("<form").count(), 2, "one per claim");
        assert!(both.contains("value=appeal"));
        assert!(both.contains("value=new-holder"));
        assert!(both.contains("New-holder claim"));

        // A ban with nothing pending: correcting the authority's own
        // error, and labelled as that rather than as an appeal.
        let uncontested = review_form(&reviewable_case_with(Some("ban"), "none", "none"));
        assert!(uncontested.contains("value=none"));
        assert!(uncontested.contains("correcting its"));
        assert!(!uncontested.contains("value=uphold"));
    }

}
