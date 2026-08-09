//! The moderator's web panel.
//!
//! It has two queues, and which one is the job depends on the
//! deployment. Under autonomous triage the classifier decides in the
//! first instance and a human reads the file on appeal; with triage off
//! a human decides every case, and **awaiting decision** is the whole
//! workload. The page says which it is rather than assuming, because
//! telling a moderator that something else decides first is a way of
//! describing their work as somebody else's problem.
//!
//! Everything is server-rendered. This screen shows disclosed evidence
//! from real cases, so it is behind a session cookie, has no
//! client-side dependencies to pull that content into, and fetches
//! nothing over the network — `panel.css` is inlined into every page
//! rather than linked.

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
        .route("/admin/audit", get(audit_log))
        .route("/admin/recovery", get(recovery_queue))
        .route("/admin/recovery/:claim_id", get(recovery_claim_detail))
        .route("/admin/recovery/:claim_id/decide", post(recovery_claim_decide))
        .route("/admin/cases/:case_id", get(case_detail))
        .route("/admin/cases/:case_id/decide", post(initial_decision))
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

// ─── Audit log ──────────────────────────────────────────────────────

async fn audit_log(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    if !authenticated(&state, &headers) {
        return Ok(Html(login_page(false)).into_response());
    }

    let events = state.store.recent_events(200)?;
    let mut body = chrome(&state, "audit");
    body.push_str(
        "<main class=wrap><h1>Audit log</h1><p class=sub>Recent activity recorded by the \
         authority, newest first. Case links open the authenticated case file.</p>",
    );
    if events.is_empty() {
        body.push_str("<div class=empty>No audit events recorded.</div>");
    } else {
        body.push_str(
            "<table class=queue><thead><tr><th>At</th><th>Case</th><th>Event</th><th>Detail</th>\
             </tr></thead><tbody>",
        );
        for (case_id, at, kind, detail) in events {
            body.push_str(&format!(
                "<tr><td class=at>{at}</td><td class=id><a href=\"/admin/cases/{id}\">{short}</a></td>\
                 <td class=ev-name>{kind}</td><td class=detail>{detail}</td></tr>",
                at = escape(&at),
                id = escape(&case_id),
                short = escape(case_id.get(..13).unwrap_or(&case_id)),
                kind = escape(&kind),
                detail = escape(&detail),
            ));
        }
        body.push_str("</tbody></table>");
    }
    body.push_str("</main>");

    Ok(Html(page("Audit log — moderation authority", &body)).into_response())
}

// ─── Device recovery claims ──────────────────────────────────────────

async fn recovery_queue(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    if !authenticated(&state, &headers) {
        return Ok(Html(login_page(false)).into_response());
    }

    let claims = state.store.open_recovery_claims()?;
    let mut body = chrome(&state, "recovery");
    body.push_str(
        "<main class=wrap><h1>Recovery claims</h1><p class=sub>People holding a marked device \
         whose identity no longer resolves — a reinstall, or a device that changed hands. \
         Each claim carries the holder's contact and their account; deciding one issues (or \
         refuses) a signed grant the device can redeem at the interface.</p>",
    );
    if claims.is_empty() {
        body.push_str("<div class=empty>No open recovery claims.</div>");
    } else {
        body.push_str(
            "<table class=queue><thead><tr><th>Filed</th><th>Claim</th><th>Grantee</th>\
             <th>Contact</th></tr></thead><tbody>",
        );
        for claim in claims {
            body.push_str(&format!(
                "<tr><td class=at>{filed}</td>\
                 <td class=id><a href=\"/admin/recovery/{id}\">{short}</a></td>\
                 <td class=id>{grantee}</td><td class=detail>{contact}</td></tr>",
                filed = escape(&claim.filed_at),
                id = escape(&claim.claim_id),
                short = escape(claim.claim_id.get(..14).unwrap_or(&claim.claim_id)),
                grantee = escape(claim.grantee.get(..21).unwrap_or(&claim.grantee)),
                contact = escape(&claim.contact),
            ));
        }
        body.push_str("</tbody></table>");
    }
    body.push_str("</main>");

    Ok(Html(page("Recovery claims — moderation authority", &body)).into_response())
}

async fn recovery_claim_detail(
    State(state): State<Arc<AppState>>,
    Path(claim_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    if !authenticated(&state, &headers) {
        return Ok(Html(login_page(false)).into_response());
    }
    let claim = state
        .store
        .recovery_claim(&claim_id)?
        .ok_or_else(|| Error::NotFound(format!("claim {claim_id}")))?;

    let mut body = chrome(&state, "recovery");
    body.push_str(&format!(
        "<main class=wrap><h1>Recovery claim {id}</h1>\
         <table class=queue><tbody>\
         <tr><td>Filed</td><td class=at>{filed}</td></tr>\
         <tr><td>State</td><td class=ev-name>{claim_state}</td></tr>\
         <tr><td>Grantee</td><td class=id>{grantee}</td></tr>\
         <tr><td>Contact</td><td class=detail>{contact}</td></tr>\
         </tbody></table>\
         <h2>Holder's account</h2><p class=detail>{statement}</p>",
        id = escape(claim.claim_id.get(..14).unwrap_or(&claim.claim_id)),
        filed = escape(&claim.filed_at),
        claim_state = escape(&claim.state),
        grantee = escape(&claim.grantee),
        contact = escape(&claim.contact),
        statement = escape(&claim.statement),
    ));

    if claim.state == "open" {
        body.push_str(&format!(
            "<h2>Decision</h2>\
             <p class=sub>Verify the holder through their contact before granting. A grant \
             authorizes one thing: moving the named case's verdict record to the grantee's \
             enrollment. The interface refuses it while any record still bans the device, so \
             a ban that should stand must be left standing (or reversed through the case \
             itself) — not worked around here.</p>\
             <form method=post action=\"/admin/recovery/{id}/decide\">\
             <label>Case — the case whose record marks this device.<br>\
             <input class=addr name=case_id placeholder=\"case-…\"></label>\
             <label>Reasoning — how the holder's account was verified, or why it was not.<br>\
             <input name=reasoning size=70 required></label>\
             <div class=actions><button class=\"sign primary\" name=outcome value=grant>Issue grant</button>\
             <button class=\"sign secondary\" name=outcome value=refuse>Refuse</button></div></form>",
            id = escape(&claim.claim_id),
        ));
    } else {
        body.push_str(&format!(
            "<h2>Decision</h2><table class=queue><tbody>\
             <tr><td>Decided</td><td class=at>{decided}</td></tr>\
             <tr><td>Case</td><td class=id>{case}</td></tr>\
             <tr><td>Reasoning</td><td class=detail>{reasoning}</td></tr>\
             </tbody></table>",
            decided = escape(claim.decided_at.as_deref().unwrap_or("—")),
            case = match claim.case_id.as_deref() {
                Some(case_id) => format!(
                    "<a href=\"/admin/cases/{0}\">{0}</a>",
                    escape(case_id)
                ),
                None => "—".into(),
            },
            reasoning = escape(claim.reasoning.as_deref().unwrap_or("—")),
        ));
    }
    body.push_str("<p><a href=/admin/recovery>← recovery claims</a></p></main>");

    Ok(Html(page("Recovery claim — moderation authority", &body)).into_response())
}

#[derive(Deserialize)]
struct RecoveryDecisionForm {
    outcome: String,
    #[serde(default)]
    case_id: String,
    reasoning: String,
}

async fn recovery_claim_decide(
    State(state): State<Arc<AppState>>,
    Path(claim_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<RecoveryDecisionForm>,
) -> Result<Response, Error> {
    if !authenticated(&state, &headers) {
        return Ok(Html(login_page(false)).into_response());
    }
    let claim = state
        .store
        .recovery_claim(&claim_id)?
        .ok_or_else(|| Error::NotFound(format!("claim {claim_id}")))?;
    let reasoning = form.reasoning.trim();
    if reasoning.is_empty() {
        return Err(Error::BadRequest("reasoning is required".into()));
    }
    let now = state.now();
    let stamp = crate::util::format_timestamp(now);

    match form.outcome.as_str() {
        "grant" => {
            let case_id = form.case_id.trim();
            let case = state
                .store
                .case(case_id)?
                .ok_or_else(|| Error::BadRequest(format!("no case {case_id:?}")))?;
            // A grant against an undecided case would race the case
            // itself; and the interface will refuse a record that
            // still bans, so granting one here only strands the
            // claimant. Say so now, to the person who can fix it.
            if case.disposition.is_none() {
                return Err(Error::CaseState(
                    "the case is still open; decide it before granting recovery".into(),
                ));
            }
            let issued = crate::recovery::issue_grant(
                &case.case_id,
                &claim.grantee,
                &state.config.manifest.component_id,
                now,
                &state.signing_key,
            )?;
            if !state.store.grant_recovery_claim(
                &claim_id,
                &case.case_id,
                reasoning,
                &issued.raw,
                &issued.grant_ref,
                &stamp,
            )? {
                return Err(Error::CaseState("the claim is no longer open".into()));
            }
            tracing::info!(%claim_id, grant_ref = %issued.grant_ref, "recovery grant issued");
        }
        "refuse" => {
            if !state.store.refuse_recovery_claim(&claim_id, reasoning, &stamp)? {
                return Err(Error::CaseState("the claim is no longer open".into()));
            }
        }
        other => {
            return Err(Error::BadRequest(format!(
                "unknown outcome {other:?} (expected grant | refuse)"
            )))
        }
    }

    Ok(Redirect::to(&format!("/admin/recovery/{claim_id}")).into_response())
}

// ─── Queue ───────────────────────────────────────────────────────────

async fn index(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, Error> {
    if !authenticated(&state, &headers) {
        return Ok(Html(login_page(false)).into_response());
    }

    let appeals = state.store.cases_awaiting_appeal_review()?;
    let undecided = state.store.cases_awaiting_decision()?;
    let recent = state.store.recent_cases(50)?;
    let now = state.now();

    // What the queues are depends on whether a classifier is running,
    // and saying the wrong one is not cosmetic. With triage off a
    // moderator decides every case in the first instance, and this page
    // used to tell them the opposite while showing their whole workload
    // as an undifferentiated "recent cases" list.
    let automated = matches!(
        state.config.triage.as_ref().map(|t| t.mode),
        Some(crate::config::TriageMode::Autonomous)
    );
    let mut body = chrome(&state, "queue");
    body.push_str("<main class=wrap>");
    body.push_str(&format!(
        "<h1>Awaiting decision</h1><p class=sub>{}</p>",
        if automated {
            "Sorted by decision deadline. Triage decides in the first instance, so what reaches \
             this queue is what it declined to decide — plus anything whose response window has \
             not closed, which cannot be decided yet either way."
        } else {
            "Sorted by decision deadline. No classifier is running, so every one of these is \
             yours, and a case nobody decides is dismissed by default when its deadline passes. \
             A case whose response window is still running cannot be decided — opening it is \
             wasted reading."
        }
    ));

    body.push_str(&format!(
        "<h2 class=k style=\"margin-top:22px\">{}</h2>",
        match undecided.len() {
            1 => "1 case".to_string(),
            n => format!("{n} cases"),
        }
    ));
    if undecided.is_empty() {
        body.push_str(
            "<div class=empty>Nothing open. A case appears here the moment a report opens one, \
             with the time remaining until its decision deadline.</div>",
        );
    } else {
        body.push_str(&decision_table(&undecided, now));
    }

    body.push_str("<h2>Appeals awaiting review</h2>");
    if appeals.is_empty() {
        body.push_str(
            "<div class=empty>No appeals are waiting. Appeals and new-holder claims appear here \
             the moment one is filed, with the stage and disposition they are contesting.</div>",
        );
    } else {
        body.push_str(&case_table(&appeals));
    }

    body.push_str(
        "<section class=recent><h2>Recent cases \
         <span class=sub style=\"display:inline;font-weight:400\">— reference, not work</span>\
         </h2>",
    );
    body.push_str(&case_table(&recent));
    body.push_str("</section></main>");

    Ok(Html(page("Queue — moderation authority", &body)).into_response())
}

/// The work queue, with the clock showing.
///
/// A separate table from `case_table` because it answers a different
/// question. That one says what happened to a case; this one says how
/// long you have, whether the accused's window has closed yet — a ban
/// before it has is refused, so a case that is not yet answerable is
/// worth distinguishing from one that is — and whether anyone has
/// replied.
fn decision_table(cases: &[CaseRecord], now: OffsetDateTime) -> String {
    let mut out = String::from(
        "<table class=queue><thead><tr><th>Case</th><th>Class</th><th>Time left</th>\
         <th>Decision deadline</th><th>Response window</th><th>Accused responded</th>\
         </tr></thead><tbody>",
    );
    for case in cases {
        let (remaining, urgency) = match util::parse_timestamp(&case.decision_deadline) {
            Ok(deadline) => (time_between(now, deadline), urgency_class(now, deadline)),
            // A deadline that will not parse is a corrupt case rather
            // than an urgent one, and saying "overdue" would send a
            // moderator to decide something the guards will refuse.
            Err(_) => ("unreadable".to_string(), "overdue"),
        };
        // A badge only where there is something to say. An ordinary
        // deadline is plain text: if every row is highlighted, the
        // highlight has stopped meaning anything.
        let remaining = match urgency {
            "" => escape(&remaining),
            class => format!("<span class=\"badge {class}\">{}</span>", escape(&remaining)),
        };
        let window_closed = util::parse_timestamp(&case.response_deadline)
            .map(|deadline| now >= deadline)
            .unwrap_or(false);
        out.push_str(&format!(
            "<tr{held}><td class=id><a href=\"/admin/cases/{id}\">{short}</a></td>\
             <td>{class}</td><td>{remaining}</td><td>{deadline}</td><td>{window}</td>\
             <td>{responded}</td></tr>",
            // Not yet decidable, so the row recedes rather than
            // disappears: it is still work, just not work for today.
            held = if window_closed { "" } else { " class=held" },
            id = escape(&case.case_id),
            short = escape(case.case_id.get(..13).unwrap_or(&case.case_id)),
            class = escape(&case.class_id),
            remaining = remaining,
            deadline = escape(&case.decision_deadline),
            window = if window_closed {
                "closed"
            } else {
                "<span class=\"badge hold\">still running — a ban is refused</span>"
            },
            responded = if case.responded { "yes" } else { "not yet" },
        ));
    }
    out.push_str("</tbody></table>");
    out
}

/// Whole days and hours, rounded down. Precision beyond that would
/// suggest the deadline is a race, and it is not — it is a date the
/// case ends on.
fn time_between(now: OffsetDateTime, deadline: OffsetDateTime) -> String {
    // How far past, not merely that it is past. An hour overdue and a
    // week overdue are different situations — the first is a case to
    // decide now, the second is one the sweep has almost certainly
    // already dismissed by default.
    if now >= deadline {
        let over = span(now - deadline);
        return match over.as_str() {
            "under an hour" => "overdue — under an hour".to_string(),
            elapsed => format!("overdue — {elapsed} past"),
        };
    }
    span(deadline - now)
}

/// Whole days and hours, rounded down.
fn span(left: time::Duration) -> String {
    let days = left.whole_days();
    let hours = left.whole_hours() - days * 24;
    match (days, hours) {
        (0, 0) => "under an hour".to_string(),
        (0, h) => format!("{h} h"),
        (d, 0) => format!("{d} d"),
        (d, h) => format!("{d} d {h} h"),
    }
}

/// The badge modifier for a deadline, or `""` for one far enough out
/// that it needs no badge at all. Names match the stylesheet's
/// `.badge.overdue` / `.badge.soon`.
fn urgency_class(now: OffsetDateTime, deadline: OffsetDateTime) -> &'static str {
    if now >= deadline {
        "overdue"
    } else if deadline - now < time::Duration::days(2) {
        "soon"
    } else {
        ""
    }
}

fn case_table(cases: &[CaseRecord]) -> String {
    let mut out = String::from(
        "<table class=queue><thead><tr><th>Case</th><th>Class</th><th>Stage</th>\
         <th>Disposition</th><th>Appeal</th><th>Opened</th></tr></thead><tbody>",
    );
    for case in cases {
        out.push_str(&format!(
            "<tr><td class=id><a href=\"/admin/cases/{id}\">{short}</a></td><td>{class}</td>\
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

    // The case file still renders its pre-design markup; only the queue
    // has been implemented from `moderator/queue.html` so far. It gets
    // the chrome and the shell so the two screens are one panel rather
    // than two, and `panel.css` carries a short compatibility section
    // keeping this legible under the new tokens until
    // `moderator/case-*.html` lands.
    let mut body = chrome(&state, "case");
    body.push_str(&format!("<main class=wrap><h1>Case {}</h1>", escape(&case.case_id)));
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

    body.push_str(&initial_decision_form(&case));
    body.push_str(&review_form(&case));
    body.push_str("<p><a href=/admin>← queue</a></p></main>");

    Ok(Html(page(&format!("Case {} — moderation authority", case.case_id), &body)).into_response())
}

fn initial_decision_form(case: &CaseRecord) -> String {
    if case.disposition.is_some() {
        return String::new();
    }

    format!(
        "<h2>Human decision</h2>\
         <p class=sub>This is the initial case decision. Choose a disposition after reading the\
         disclosed evidence. A ban is still subject to notice, response-window, and decision-deadline\
         safeguards.</p>\
         <form method=post action=\"/admin/cases/{id}/decide\">\
         <label>Reasoning — a content address of your findings against the consented class definition.\
         <br><input name=reasoning size=70 placeholder=\"sha256:… or https://…\" required></label><br>\
         <label>Appeal URL — where the accused files an appeal.<br>\
         <input class=addr name=appeal_url type=url placeholder=\"https://…\" required></label>\
         <label>New-holder URL — where a new device holder clears the mark.<br>\
         <input class=addr name=new_holder_url type=url placeholder=\"https://…\" required></label>\
         <label>Authority contact — human-readable appeal contact.<br>\
         <input class=addr name=authority_contact placeholder=\"appeals@example.org\" required></label>\
         <div class=actions><button class=\"sign primary\" name=outcome value=ban>Ban</button>\
         <button class=\"sign secondary\" name=outcome value=dismiss formnovalidate>Dismiss</button></div></form>",
        id = escape(&case.case_id),
    )
}

#[derive(Deserialize)]
struct InitialDecisionForm {
    outcome: String,
    reasoning: String,
    #[serde(default)]
    appeal_url: String,
    #[serde(default)]
    new_holder_url: String,
    #[serde(default)]
    authority_contact: String,
}

async fn initial_decision(
    State(state): State<Arc<AppState>>,
    Path(case_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<InitialDecisionForm>,
) -> Result<Response, Error> {
    if !authenticated(&state, &headers) {
        return Ok(Html(login_page(false)).into_response());
    }

    let disposition = Disposition::parse(&form.outcome)?;
    if !matches!(disposition, Disposition::Ban | Disposition::Dismiss) {
        return Err(Error::BadRequest("initial decisions may only ban or dismiss".into()));
    }

    let routes = if disposition == Disposition::Ban {
        Some(decisions::AppealRoutes {
            appeal_url: form.appeal_url,
            new_holder_url: form.new_holder_url,
            authority_contact: form.authority_contact,
        })
    } else {
        None
    };

    decisions::apply_with_appeal_routes(
        &state,
        &case_id,
        disposition,
        &form.reasoning,
        Decider::Human,
        state.now(),
        routes,
    )
    .await?;

    Ok(Redirect::to(&format!("/admin/cases/{case_id}")).into_response())
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

    // What this page was rendered from. A pending appeal can be
    // supplemented without leaving `pending`, and another moderator can
    // answer the same claim while this page sits open — neither moves
    // the case revision. Posting the value back is what lets the
    // decision transaction refuse a review of a file that has changed
    // since it was read.
    //
    // It rides with the reasoning field so that every form on this
    // page carries it, including any added later.
    let reasoning_field = format!(
        "<input type=hidden name=claim_revision value={read_at}>\
         <label>Reasoning — a content address of your findings against the \
         consented class definition, not a sentence.<br>\
         <input name=reasoning size=70 placeholder=\"sha256:… or https://…\" required></label><br>",
        read_at = case.claim_revision
    );
    let reasoning_field = &reasoning_field;

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
    /// The case's `claim_revision` when the page was rendered. Carried
    /// into the decision transaction so a supplementary filing, or
    /// another moderator answering the same claim, refuses this review
    /// rather than letting it commit against a file it never read.
    /// Absent on an older form post, which is checked as before.
    #[serde(default)]
    claim_revision: Option<i64>,
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
        // `none` is what the "Correct this verdict" form posts, and it
        // reached the `other` arm below: the one control `review_form`
        // renders for an uncontested ban always 400'd. It resolves the
        // same way as an absent subject, which already computes `none`
        // for itself — so an explicit `none` posted while something is
        // pending still answers that claim rather than reversing past
        // it and leaving it queued forever.
        "" | "none" => {
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
                    // The state this review was decided against. Two
                    // moderators opening the same case would otherwise
                    // both pass the pending check and both record a
                    // review of it.
                    Some("pending"),
                    // And the revision it was decided against, which
                    // the state alone does not give: a claim filed
                    // beside this one leaves it `pending` while adding
                    // material this review did not read.
                    form.claim_revision,
                    &stamp,
                    "new_holder_claim_refused",
                    &form.reasoning,
                )?;
            } else {
                state.store.set_appeal_state(
                    &case_id,
                    "upheld",
                    Some("pending"),
                    form.claim_revision,
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
            decisions::apply_reviewing(
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
                // The claim this form answered. Without it a reversal
                // resolved both, so granting the unauthenticated
                // new-holder claim also recorded the accused's appeal
                // as reversed — a review nobody performed.
                if subject == "new-holder" {
                    decisions::Claim::NewHolder
                } else {
                    decisions::Claim::Appeal
                },
                // The file this reviewer actually read. A supplement
                // that landed after the page was rendered, or another
                // moderator's answer to the same claim, refuses the
                // commit instead of being decided past.
                form.claim_revision,
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

/// The document shell. `body` is everything inside `<body>` — the
/// header chrome included — because the signed-in pages carry one and
/// the sign-in gate deliberately does not.
fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8>\
         <meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>{title}</title><style>{STYLE}</style></head><body>{body}</body></html>",
        title = escape(title),
        body = body,
        STYLE = STYLE
    )
}

/// Header for a signed-in page. `here` marks the current nav item.
///
/// Sign out is a POST rather than a link, styled to read as one. A
/// session must not end on a GET: anything that can make the browser
/// issue one — a prefetch, an image tag in disclosed evidence — could
/// otherwise sign a moderator out mid-review.
fn chrome(state: &AppState, here: &str) -> String {
    let authority = escape(&state.config.manifest.component_id);
    let queue_current = if here == "queue" { " aria-current=page" } else { "" };
    let audit_current = if here == "audit" { " aria-current=page" } else { "" };
    let recovery_current = if here == "recovery" { " aria-current=page" } else { "" };
    format!(
        "<header class=top><div class=wrap>\
         <span class=brand>moderation authority <span>· {authority}</span></span>\
         <nav><a href=/admin{queue_current}>Queue</a>\
         <a href=/admin/recovery{recovery_current}>Recovery</a>\
         <a href=/admin/audit{audit_current}>Audit log</a>\
         <form method=post action=/admin/logout>\
         <button class=linkish type=submit>Sign out</button></form>\
         </nav></div></header>"
    )
}

fn login_page(failed: bool) -> String {
    let error = if failed { "<p class=error>That token was not accepted.</p>" } else { "" };
    page(
        "Sign in",
        &format!(
            "<div class=gate><form method=post action=/admin/login class=panel>\
             <div><h1 style=\"margin:0 0 6px\">Moderation panel</h1>\
             <p class=sub>Cases decided here end with a signed verdict.</p></div>\
             <div class=warnbox><div><b>This screen shows disclosed evidence.</b>\
             Do not open it where it can be read over your shoulder.</div></div>{error}\
             <label class=field>Moderator token\
             <input class=addr name=token type=password autocomplete=current-password required>\
             </label>\
             <button class=sign>Sign in</button></form></div>"
        ),
    )
}

/// The panel stylesheet, kept as a real CSS file so it stays diffable
/// against the design it came from rather than living inside a Rust
/// string literal. Inlined into every page: this screen holds disclosed
/// evidence and pulls nothing over the network.
const STYLE: &str = include_str!("panel.css");

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
            revision: 0,
            claim_revision: 0,
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
            Form(ReviewForm { outcome: "uphold".into(), reasoning: "hash:reviewed".into(), subject: String::new(), claim_revision: None }),
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
            Form(ReviewForm { outcome: "reverse".into(), reasoning: "hash:reviewed".into(), subject: String::new(), claim_revision: None }),
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
            Form(ReviewForm { outcome: "uphold".into(), reasoning: "hash:reviewed".into(), subject: String::new(), claim_revision: None }),
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
            Form(ReviewForm { outcome: "uphold".into(), reasoning: "hash:reviewed".into(), subject: String::new(), claim_revision: None }),
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
            Form(ReviewForm { outcome: "reverse".into(), reasoning: "hash:reviewed".into(), subject: String::new(), claim_revision: None }),
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
                claim_revision: None,
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
                claim_revision: None,
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
                claim_revision: None,
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


    /// A reversal resolves the claim that was *reviewed*. Resolving
    /// both recorded a claim nobody had read as decided: granting the
    /// unauthenticated new-holder claim also marked the accused's
    /// appeal reversed, and reversing on the appeal granted the
    /// stranger's claim. The other becomes moot — the marks are gone,
    /// so its remedy has arrived — without a review being invented.
    #[tokio::test]
    async fn a_reversal_resolves_only_the_claim_that_was_reviewed() {
        let state = Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&reviewable_case_with(Some("ban"), "pending", "pending")).unwrap();
        state.store.put_delivered_open_case_verdict("c1", "v-open").unwrap();

        review(
            State(state.clone()),
            Path("c1".to_string()),
            signed_in(&state),
            Form(ReviewForm {
                outcome: "reverse".into(),
                reasoning: "hash:claim".into(),
                subject: "new-holder".into(),
                claim_revision: None,
            }),
        )
        .await
        .unwrap();

        let case = state.store.case("c1").unwrap().unwrap();
        assert_eq!(case.disposition.as_deref(), Some("reversed"), "the marks are cleared");
        assert_eq!(case.new_holder_state, "granted", "the claim that was read");
        assert_eq!(
            case.appeal_state, "moot",
            "the appeal's remedy arrived, but nobody reviewed it"
        );

        let events = state.store.events("c1").unwrap();
        assert!(events.iter().any(|(_, kind, _)| kind == "new_holder_claim_granted"));
        assert!(
            !events.iter().any(|(_, kind, _)| kind == "appeal_reversed"),
            "an appeal nobody read must not be recorded as reversed"
        );
    }


    /// Two moderators opening the same case both pass the "is it
    /// pending?" check; the write must not let both record a review.
    #[tokio::test]
    async fn only_one_moderator_can_record_a_review_of_the_same_claim() {
        let state = Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&reviewable_case_with(Some("ban"), "pending", "none")).unwrap();

        let uphold = || {
            review(
                State(state.clone()),
                Path("c1".to_string()),
                signed_in(&state),
                Form(ReviewForm {
                    outcome: "uphold".into(),
                    reasoning: "hash:reviewed".into(),
                    subject: "appeal".into(),
                    claim_revision: None,
                }),
            )
        };
        uphold().await.unwrap();
        let second = uphold().await;

        assert!(second.is_err(), "the second review must not land on an answered appeal");
        assert_eq!(state.store.case("c1").unwrap().unwrap().appeal_state, "upheld");
        assert_eq!(
            state
                .store
                .events("c1")
                .unwrap()
                .iter()
                .filter(|(_, kind, _)| kind == "appeal_upheld")
                .count(),
            1,
            "one review, one record of it"
        );
    }

    /// The value the "Correct this verdict" form actually posts, taken
    /// out of the rendered HTML rather than written out again here.
    ///
    /// Asserting that the page *contains* `value=none` is what let this
    /// break: the handler rejected `"none"` as an unknown subject, so
    /// the one control rendered for an uncontested ban returned 400
    /// every time. A test that reads the form and posts it is the only
    /// kind that can tell.
    #[tokio::test]
    async fn the_form_for_an_uncontested_ban_posts_something_the_handler_accepts() {
        let state = Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        let case = reviewable_case_with(Some("ban"), "none", "none");
        state.store.put_case(&case).unwrap();
        state.store.put_delivered_open_case_verdict("c1", "v-open").unwrap();

        let rendered = review_form(&case);
        let subject = rendered
            .split("name=subject value=")
            .nth(1)
            .and_then(|rest| rest.split('>').next())
            .expect("the form names a subject")
            .to_string();

        review(
            State(state.clone()),
            Path("c1".to_string()),
            signed_in(&state),
            Form(ReviewForm {
                outcome: "reverse".into(),
                reasoning: "hash:our-own-error".into(),
                subject,
                claim_revision: Some(case.claim_revision),
            }),
        )
        .await
        .expect("the panel's own form must not be refused");

        let case = state.store.case("c1").unwrap().unwrap();
        assert_eq!(case.disposition.as_deref(), Some("reversed"));
        assert!(
            !state.store.events("c1").unwrap().iter().any(|(_, kind, _)| kind == "appeal_reversed"),
            "nobody appealed; this is the authority correcting itself"
        );
    }

    /// An explicit `none` on a case that *does* have something pending
    /// answers it, rather than reversing past it and leaving the claim
    /// queued against a case whose marks are already gone.
    #[tokio::test]
    async fn an_explicit_none_still_answers_whatever_is_pending() {
        let state = Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&reviewable_case_with(Some("ban"), "pending", "none")).unwrap();
        state.store.put_delivered_open_case_verdict("c1", "v-open").unwrap();

        review(
            State(state.clone()),
            Path("c1".to_string()),
            signed_in(&state),
            Form(ReviewForm {
                outcome: "reverse".into(),
                reasoning: "hash:reviewed".into(),
                subject: "none".into(),
                claim_revision: None,
            }),
        )
        .await
        .unwrap();

        assert_eq!(state.store.case("c1").unwrap().unwrap().appeal_state, "reversed");
    }

    /// The page carries what it was rendered from, so the decision can
    /// be refused if the file changed underneath it.
    #[test]
    fn the_review_form_carries_the_claim_revision_it_was_rendered_at() {
        let mut case = reviewable_case_with(Some("ban"), "pending", "none");
        case.claim_revision = 7;
        assert!(review_form(&case).contains("name=claim_revision value=7"));
    }

    /// The accused may supplement a pending appeal, which leaves it
    /// `pending` and leaves the case document untouched — so neither
    /// the state check nor the case revision notices. A moderator who
    /// loaded the page before the supplement would otherwise commit a
    /// review of a file they never read.
    #[tokio::test]
    async fn a_supplement_filed_after_the_page_loaded_refuses_the_review() {
        let state = Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&reviewable_case_with(Some("ban"), "pending", "none")).unwrap();
        state.store.put_delivered_open_case_verdict("c1", "v-open").unwrap();

        // What the page was rendered at.
        let read_at = state.store.case("c1").unwrap().unwrap().claim_revision;

        // …and then the accused files more material.
        state
            .store
            .append_claim_event_bounded("c1", "2026-08-10T00:00:00Z", "appeal_filed", "and also", 8)
            .unwrap();

        for outcome in ["uphold", "reverse"] {
            let result = review(
                State(state.clone()),
                Path("c1".to_string()),
                signed_in(&state),
                Form(ReviewForm {
                    outcome: outcome.into(),
                    reasoning: "hash:reviewed".into(),
                    subject: "appeal".into(),
                    claim_revision: Some(read_at),
                }),
            )
            .await;
            assert!(matches!(result, Err(Error::CaseState(_))), "{outcome}: {result:?}");
        }

        let case = state.store.case("c1").unwrap().unwrap();
        assert_eq!(case.appeal_state, "pending", "still waiting for a review of the whole file");
        assert_eq!(case.disposition.as_deref(), Some("ban"));
    }

    /// Two moderators, one claim, and one of them reads a page rendered
    /// before the other answered it. The state check catches an
    /// `uphold` racing an `uphold`; it does not catch a `reverse`
    /// racing an `uphold`, because a reversal is guarded on the
    /// disposition, which is still `ban`.
    #[tokio::test]
    async fn a_reversal_cannot_commit_against_a_claim_someone_else_upheld() {
        let state = Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&reviewable_case_with(Some("ban"), "pending", "none")).unwrap();
        state.store.put_delivered_open_case_verdict("c1", "v-open").unwrap();

        let read_at = state.store.case("c1").unwrap().unwrap().claim_revision;

        // The other moderator gets there first.
        review(
            State(state.clone()),
            Path("c1".to_string()),
            signed_in(&state),
            Form(ReviewForm {
                outcome: "uphold".into(),
                reasoning: "hash:upheld".into(),
                subject: "appeal".into(),
                claim_revision: Some(read_at),
            }),
        )
        .await
        .unwrap();

        let result = review(
            State(state.clone()),
            Path("c1".to_string()),
            signed_in(&state),
            Form(ReviewForm {
                outcome: "reverse".into(),
                reasoning: "hash:reversed".into(),
                subject: "appeal".into(),
                claim_revision: Some(read_at),
            }),
        )
        .await;

        assert!(matches!(result, Err(Error::CaseState(_))), "{result:?}");
        let case = state.store.case("c1").unwrap().unwrap();
        assert_eq!(case.appeal_state, "upheld");
        assert_eq!(case.disposition.as_deref(), Some("ban"), "the first review stands");
    }

    // ─── The decision queue ──────────────────────────────────────────

    fn open_case_due(case_id: &str, decision_deadline: &str, response_deadline: &str) -> CaseRecord {
        let mut case = reviewable_case(None, "none");
        case.case_id = case_id.into();
        // One open case per accused per class is enforced by a unique
        // index, so distinct people — which is also what a queue of
        // several open cases means in the first place.
        case.accused = format!("onym:key:{case_id}");
        case.stage = "open".into();
        case.decision_deadline = decision_deadline.into();
        case.response_deadline = response_deadline.into();
        case
    }

    /// The ordering *is* the feature. A moderator working without a
    /// classifier has a queue with a clock on it, and "recent cases"
    /// sorted by when they opened puts the case about to expire
    /// wherever it happens to fall.
    #[test]
    fn the_decision_queue_puts_the_soonest_deadline_first() {
        let store = Store::in_memory().unwrap();
        // Deliberately inserted newest-deadline-first, and opened in
        // the opposite order to their deadlines, so neither insertion
        // order nor `opened_at` could produce the right answer.
        for (id, deadline) in [
            ("c-late", "2026-08-30T00:00:00Z"),
            ("c-soon", "2026-08-11T00:00:00Z"),
            ("c-middle", "2026-08-20T00:00:00Z"),
        ] {
            store.put_case(&open_case_due(id, deadline, "2026-08-04T00:00:00Z")).unwrap();
        }
        // A decided case is not work, however old it is.
        let mut decided = open_case_due("c-done", "2026-08-09T00:00:00Z", "2026-08-04T00:00:00Z");
        decided.stage = "decided".into();
        decided.disposition = Some("dismiss".into());
        store.put_case(&decided).unwrap();

        let queue: Vec<String> =
            store.cases_awaiting_decision().unwrap().into_iter().map(|c| c.case_id).collect();
        assert_eq!(queue, vec!["c-soon", "c-middle", "c-late"]);
    }

    /// Without a classifier the page has to say so. It used to tell a
    /// moderator that "triage decides in the first instance" while
    /// showing them every case they were personally responsible for as
    /// undifferentiated background.
    #[tokio::test]
    async fn the_queue_is_rendered_with_the_time_remaining() {
        let state = Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        // The fixture clock is 2026-08-10.
        state.store.put_case(&open_case_due("c-soon", "2026-08-11T06:00:00Z", "2026-08-04T00:00:00Z")).unwrap();
        state.store.put_case(&open_case_due("c-late", "2026-08-30T00:00:00Z", "2026-08-20T00:00:00Z")).unwrap();

        let response = index(State(state.clone()), signed_in(&state)).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let page = String::from_utf8(body.to_vec()).unwrap();

        assert!(page.contains("<h1>Awaiting decision</h1>"), "the queue leads the page");
        assert!(page.contains("2 cases"), "and is counted: {page}");
        assert!(page.contains("1 d 6 h"), "time remaining is shown: {page}");
        assert!(
            page.contains("class=\"badge soon\""),
            "a deadline inside two days is badged, not merely coloured"
        );
        assert!(
            page.contains("No classifier is running"),
            "with no classifier the page must not claim triage decides first"
        );
        // Sign out ends a session, so it must not be reachable by a GET
        // that disclosed evidence could trigger.
        assert!(page.contains("<form method=post action=/admin/logout>"), "sign out is a POST");
        // A case whose response window is still running cannot be
        // banned yet, and saying so stops a moderator opening it,
        // reading the file and being refused.
        assert!(page.contains("still running — a ban is refused"), "{page}");
        assert!(page.contains("closed"));
    }

    /// The page pulls nothing over the network. It renders evidence a
    /// stranger wrote, so a linked stylesheet, font or image would be a
    /// request a hostile document could observe or a network could
    /// block — and the panel would then be unstyled at exactly the
    /// moment it is showing the most sensitive thing it has.
    #[tokio::test]
    async fn the_panel_fetches_nothing() {
        let state = Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&open_case_due("c1", "2026-08-20T00:00:00Z", "2026-08-04T00:00:00Z")).unwrap();

        let response = index(State(state.clone()), signed_in(&state)).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let page = String::from_utf8(body.to_vec()).unwrap();

        assert!(page.contains("<style>"), "the stylesheet is inlined");
        for offender in ["<link", "<script", "<img", "src=", "@import", "url(http"] {
            assert!(!page.contains(offender), "panel must not reference {offender}: {page}");
        }
        // And the design's tokens actually shipped, rather than the
        // markup arriving with the old stylesheet behind it.
        assert!(page.contains("--overdue"), "panel.css is the sheet being served");
    }

    #[test]
    fn time_remaining_reads_as_a_date_rather_than_a_race() {
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();
        let at = |s: &str| util::parse_timestamp(s).unwrap();

        assert_eq!(time_between(now, at("2026-08-13T00:00:00Z")), "3 d");
        assert_eq!(time_between(now, at("2026-08-13T05:00:00Z")), "3 d 5 h");
        assert_eq!(time_between(now, at("2026-08-10T05:00:00Z")), "5 h");
        assert_eq!(time_between(now, at("2026-08-10T00:30:00Z")), "under an hour");

        // Overdue says *how far* past. An hour and a week are different
        // situations: the first is a case to decide now, the second is
        // one the sweep has almost certainly already dismissed.
        assert_eq!(time_between(now, at("2026-08-09T13:00:00Z")), "overdue — 11 h past");
        assert_eq!(time_between(now, at("2026-08-09T00:00:00Z")), "overdue — 1 d past");
        // Exactly at the deadline is past it: the case is dismissed by
        // default at that instant, not a moment after.
        assert_eq!(time_between(now, now), "overdue — under an hour");

        assert_eq!(urgency_class(now, at("2026-08-30T00:00:00Z")), "");
        assert_eq!(urgency_class(now, at("2026-08-11T00:00:00Z")), "soon");
        assert_eq!(urgency_class(now, at("2026-08-01T00:00:00Z")), "overdue");
    }

    // ─── Recovery claims ─────────────────────────────────────────────

    fn open_claim(state: &AppState) -> String {
        let claim = crate::store::RecoveryClaim {
            claim_id: "claim-1".into(),
            grantee: "onym:key:new-holder".into(),
            contact: "holder@example.org".into(),
            statement: "Bought this device second-hand.".into(),
            filed_at: "2026-08-09T00:00:00Z".into(),
            state: "open".into(),
            case_id: None,
            decided_at: None,
            reasoning: None,
            grant_raw: None,
        };
        assert!(state.store.file_recovery_claim(&claim).unwrap());
        claim.claim_id
    }

    fn recovery_form(outcome: &str, case_id: &str) -> RecoveryDecisionForm {
        RecoveryDecisionForm {
            outcome: outcome.into(),
            case_id: case_id.into(),
            reasoning: "verified the holder by phone".into(),
        }
    }

    /// A grant against a case nobody has decided would race the case
    /// itself; the panel refuses it with the reason, not the interface
    /// later with a stranded claimant.
    #[tokio::test]
    async fn granting_recovery_requires_a_decided_case() {
        let state = Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&reviewable_case(None, "none")).unwrap();
        let claim_id = open_claim(&state);

        let result = recovery_claim_decide(
            State(state.clone()),
            Path(claim_id.clone()),
            signed_in(&state),
            Form(recovery_form("grant", "c1")),
        )
        .await;

        assert!(matches!(result, Err(Error::CaseState(_))), "{result:?}");
        assert_eq!(state.store.recovery_claim(&claim_id).unwrap().unwrap().state, "open");
    }

    #[tokio::test]
    async fn a_recovery_grant_is_signed_recorded_and_single_decision() {
        use ed25519_dalek::Verifier;

        let state = Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&reviewable_case(Some("reversed"), "reversed")).unwrap();
        let claim_id = open_claim(&state);

        recovery_claim_decide(
            State(state.clone()),
            Path(claim_id.clone()),
            signed_in(&state),
            Form(recovery_form("grant", "c1")),
        )
        .await
        .unwrap();

        let claim = state.store.recovery_claim(&claim_id).unwrap().unwrap();
        assert_eq!(claim.state, "granted");
        assert_eq!(claim.case_id.as_deref(), Some("c1"));

        // The stored grant is what the claimant's device will present:
        // it must verify against this authority's operator key over
        // the canonical bytes, name the grantee and the case.
        let raw = claim.grant_raw.expect("grant bytes stored");
        let grant: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(grant["grantee"], "onym:key:new-holder");
        assert_eq!(grant["caseId"], "c1");
        assert_eq!(grant["authority"], state.config.manifest.component_id);
        let signing_bytes = crate::canonical::grant_signing_bytes(&raw).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(
            &util::base64_decode(grant["signature"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        state.signing_key.verifying_key().verify(&signing_bytes, &signature).unwrap();

        // On the case ledger, so the audit log shows the authorization.
        let events = state.store.recent_events(10).unwrap();
        assert!(events.iter().any(|(case_id, _, kind, detail)| case_id == "c1"
            && kind == "recovery_grant_issued"
            && detail.contains(&claim_id)));

        // A decided claim cannot be decided again.
        let again = recovery_claim_decide(
            State(state.clone()),
            Path(claim_id),
            signed_in(&state),
            Form(recovery_form("refuse", "")),
        )
        .await;
        assert!(matches!(again, Err(Error::CaseState(_))), "{again:?}");
    }

    #[tokio::test]
    async fn refusing_a_recovery_claim_records_the_reasons() {
        let state = Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        let claim_id = open_claim(&state);

        recovery_claim_decide(
            State(state.clone()),
            Path(claim_id.clone()),
            signed_in(&state),
            Form(recovery_form("refuse", "")),
        )
        .await
        .unwrap();

        let claim = state.store.recovery_claim(&claim_id).unwrap().unwrap();
        assert_eq!(claim.state, "refused");
        assert_eq!(claim.reasoning.as_deref(), Some("verified the holder by phone"));
        assert!(claim.grant_raw.is_none());
    }

    /// The decide endpoint is a signed-in surface like every other
    /// panel action: no session, no decision — and the claim is left
    /// exactly as it was.
    #[tokio::test]
    async fn recovery_decisions_require_a_session() {
        let state = Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&reviewable_case(Some("reversed"), "reversed")).unwrap();
        let claim_id = open_claim(&state);

        recovery_claim_decide(
            State(state.clone()),
            Path(claim_id.clone()),
            HeaderMap::new(),
            Form(recovery_form("grant", "c1")),
        )
        .await
        .unwrap();

        assert_eq!(state.store.recovery_claim(&claim_id).unwrap().unwrap().state, "open");
    }
}
