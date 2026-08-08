# onym-moderation / authority

Reference **moderation authority** for the Onym moderation seat —
the other half of [`../apple`](../apple), and owned by a different
operator on purpose.

Implements the operations of
[`Moderation.md`](https://github.com/onymchat/onym-system/blob/main/moderation/Moderation.md)
§6: accept-mandate, file-report, serve-notice, respond, issue-verdict,
appeal, query-status.

## The division, restated

| | Authority (here) | Interface (`../apple`) |
|---|---|---|
| Holds | verdict signing keys, procedure, judgment | the DeviceCheck key |
| Can | open cases, decide them, sign verdicts | read and write device marks |
| Cannot | write a mark — there is no code path to one | originate a verdict |

*The authority's key can sign verdicts; it can never write marks. The
interface can write marks; it can never originate them* (§5.7). If a
future change gives this service a write path to a device, the seat's
separation is gone, whatever the docs say.

## What it will not do

Enumerated because a moderation service's restraint is the part worth
reviewing:

- **No jurisdiction without consent.** Reports are accepted only
  against an accused who signed a mandate naming this authority, and
  only from reporters whose own mandate names it. Abuse from a user of
  another interface is refused (`no_jurisdiction`) rather than judged.
- **No evidence without authenticity.** Every disclosed item must
  verify against the accused's key. Content without a proof is a
  complaint, not evidence, and cannot support a verdict.
- **No sanction before notice.** A ban is refused until the consented
  response window has *elapsed* — answering early does not shorten it,
  because the accused was promised the time, not merely one chance to
  speak. Joined evidence with different disclosed material or context
  produces another signed notice and restarts the response window; the
  case's fixed decision deadline never moves. Byte-identical evidence
  is already before the accused and does not restart the window. Every
  notice must reach the interface before a ban can issue. A ban is also
  refused once the decision deadline has passed, since by then the case
  is already dismissed by default. The case-open mark is the only
  pre-verdict effect.
- **No unexplained verdicts.** `reasoning` is required on every
  disposition, including dismissals and case openings.
- **No case without consent to *these* terms.** Every mandate is stored
  with the exact manifest bytes it pinned, and cases are judged by
  those — republishing the manifest with a longer ban term does not
  re-term anyone who consented before it.

- **No unverifiable jurisdiction.** With no interface countersigning key
  configured, mandate registration is refused rather than accepted on
  trust: an unverifiable designation is exactly the forgery the check
  exists to catch.

- **No bounty.** Reporters build an authority-local, pseudonymous,
  non-transferable track record that weights intake. Nothing is paid
  for a report, and nothing about a ban pays more than a dismissal.
- **No scanning.** There is no endpoint that ingests content nobody
  disclosed, and no path that reads a mailbox or a key.

## Undecided is dismissal

The invariant that keeps a stalled authority from acquiring hostage
power (§3.5, §11.6): every case carries a decision deadline from the
manifest, and when it passes without a decision the case is dismissed
and the case-open mark cleared — with no action by anyone.

`deadlines.rs` sweeps for overdue cases on an interval and issues the
default dismissal. It compares wall-clock times rather than elapsed
process time, so a service that was down across a deadline still
honours it on the way back up. A blown deadline is a dismissal, not an
extension nobody consented to.

## The manifest is the authority's whole power

`/manifest.json` is served **byte-for-byte** as published, because a
user's mandate pins the SHA-256 of exactly those bytes. Two consequences
worth stating:

- Editing the file after anyone has consented silently invalidates
  their mandates — their consent was to the old bytes.
- The `operator` field must name the key this service signs with, or
  every verdict it issues is refused downstream. The service checks
  this at boot and **exits** rather than running as an authority whose
  output nobody can verify — a warning produced a service that looked
  healthy, decided cases, and moved no marks.
- Once `validUntil` has passed, no new mandate is accepted and no new
  case is opened — this authority's own manifest and the one the
  accused's mandate pinned must *both* still be live. Cases already
  open still run to their deadlines: an expiry must not strand someone
  under a case-open mark.

## How a case is decided

Three configurations, chosen with `AUTHORITY_TRIAGE_MODE`:

| Mode | Who decides | Where a human enters |
|---|---|---|
| `off` | a moderator, via the API or the panel | every case |
| `advisory` | a moderator, shown the classifier's recommendation | every case |
| `autonomous` | the classifier | **on appeal** |

`autonomous` is the shape this was built for: a locally-hosted
moderation model triages each case, and a person reads the file when
someone says the machine got it wrong. Appeals are the panel's queue.

Whatever the mode, three things do not change:

- **A ban waits for the response window.** Triage may reach a ban the
  moment a report lands; the verdict is deferred until the accused's
  consented window has elapsed — answering early does not release it,
  because the window is time they were promised rather than one chance
  to speak. A classifier's certainty is not a reason to shorten it, so
  the guard lives in `decisions.rs` where all three callers inherit it.
- **A ban after the decision deadline is refused.** By then the case is
  already dismissed by default, and a decider must not win that race
  against the sweep.
- **A dismissal lands immediately.** It is not a sanction, and making
  someone wait for one helps nobody.
- **Undecided is still dismissal.** If the model is down and no human
  arrives, the case hits its decision deadline and dismisses itself.

## The model runs on this host

`AUTHORITY_TRIAGE_URL` defaults to a sibling container, and the service
logs an error at boot if it points anywhere else.

Case evidence is content a recipient disclosed *for adjudication*.
Sending it to a third party's API is a further disclosure — one the
manifest's confidentiality policy would have to declare (§8 obligation
6) and that users consented without being told about. Keeping inference
local means the disclosed content stays with the operator who was
consented to.

The client speaks the documented moderation shape
(`POST /v1/moderations` with `{model, input}`), and accepts both
response forms the API has used — the older `results[].category_scores`
and the newer `guardrails[].*.categories`. What can serve that shape
locally depends on your licensing, so the compose file leaves the image
to the operator rather than pinning one this project cannot verify.

**A response it cannot parse is an error, never a clean result.** The
tempting failure mode — unrecognised JSON, no categories, score zero,
dismiss — would turn every outage into an acquittal.

## Category mapping

A model's categories are not violation classes. `sexual` is not an
offence; `unsolicited-pornography` is, and only the manifest says so.
`AUTHORITY_TRIAGE_CATEGORY_MAP` is where you assert the correspondence,
and a class with no mapping is scored as inconclusive rather than given
an invented number.

Only categories mapped to the case's class count toward its score, so a
case about one class cannot be decided by a model's opinion about
conduct nobody consented to have judged.

## The moderator panel

Server-rendered at `/admin`, behind `AUTHORITY_ADMIN_TOKEN` and a
session cookie (`HttpOnly`, `SameSite=Strict`, `Secure`). Its queue is
appeals; it also lists recent cases for oversight.

A case page shows the disclosed evidence, the classifier's per-category
scores and what the class was judged on, the case history, and the
content address the verdict's reasoning points at. The reporter's
identity is deliberately absent — it is visible to the authority, never
to the accused, and a reviewer does not need it to weigh evidence.

Upholding an appeal issues no verdict: the one in force already says
what it says. Reversing issues a fresh verdict that clears the marks,
which is the only conforming way to undo one (§12). Either way the
decision is recorded as `human-assisted`, because the reviewer saw the
classifier's assessment on the way there.

Everything rendered goes through one escaping function. The evidence
*is* text a stranger wrote, so that is the boundary between a case file
and the moderator's session.

## Endpoints

| Method | Path | |
|---|---|---|
| `GET` | `/manifest.json` | The published manifest, verbatim |
| `POST` | `/v1/mandates` | accept-mandate: the interface registers a user's mandate |
| `POST` | `/v1/reports` | file-report: signed report with authenticity proofs |
| `POST` | `/v1/cases/:id/respond` | The accused's response |
| `POST` | `/v1/cases/:id/appeal` | Appeal, or a new-holder claim |
| `GET` | `/v1/cases/:id/status` | query-status, per the confidentiality policy — requires a party credential |
| `POST` | `/v1/cases/:id/decide` | The moderator's judgment (bearer token) |
| `POST` | `/v1/verdicts/:ref/requeue` | Requeue a repaired permanent delivery refusal (moderator bearer token) |
| `GET` | `/admin` | Moderator panel — appeal queue, case files, review |
| `GET` | `/health` | Signing key, manifest hash, whether it can decide or deliver, and how many verdicts the interface refuses |

`/v1/cases/:id/decide` is the only path from a report to a sanction,
and it needs a human's token. There is no automatic escalation.

Party `query-status` credentials travel in `X-Onym-Key`,
`X-Onym-Timestamp`, and `X-Onym-Signature` headers. The signature covers
`query-status:<caseId>:<timestamp>` and expires after five minutes; it is
never placed in the request URI or Caddy access log.

A case id is not a credential. `query-status` answers the accused, a
reporter on the case, or a moderator; a party proves who they are by
signing `query-status:<caseId>:<timestamp>` with the key that made them
one and placing the key, timestamp, and signature in the headers above.
A stranger gets the same answer as for a case that does not exist,
because a distinguishable refusal would confirm that a named person is
under investigation.

Every refusal on that endpoint looks the same — bad signature, right
key; good signature, wrong key; a case that does not exist. Checking
membership before the signature would answer a question the caller had
proved no right to ask.

`respond` and `appeal` carry `caseId` **inside** the signed bytes. Left
out, a signed "that wasn't me" could be lifted from one case and
replayed onto another as an answer to an accusation its signer never
saw.

## Delivery can fail, and failing is not deciding

A verdict is signed and stored whether or not the interface is
reachable; an undelivered verdict is a delivery problem, never an
undecided case. Unreachable and 5xx are retried indefinitely.

A **4xx is different**: the interface refused the verdict's shape, and
identical bytes will be refused identically forever. Refusals are
counted separately from unreachability — an interface down for three
sweeps must not make the next 4xx the last straw — and after three
*refusals* the verdict is marked undeliverable and stops being retried —
not deleted, and not treated as delivered. It appears in `/health` as
`undeliverableVerdicts` with the interface's own error, because each
one is a mark that should have moved and did not: for a dismissal
somebody stays marked, and for a ban a sanction the authority believes
it issued is in force nowhere. Re-POSTing it every five minutes turned
that into a log line nobody reads.

## A canonicalization hazard worth knowing

Signing bytes are the JSON with the signature field removed
structurally and keys sorted by **UTF-8 byte order**.

Foundation ships two `.sortedKeys` implementations that disagree:
`JSONEncoder` sorts by byte order (matching this service and
serde_json), while `JSONSerialization` sorts case-insensitively. Of the
boundary objects, only `Report` has keys that collide under that
difference — `reportId` and `reportVersion` sort before `reporter` by
byte order and after it case-insensitively. `mandate`, `verdict`, and
`notice` sort identically under both rules, which is why the interface
interoperates today.

The consequence: a client whose canonicalization ends in
`JSONSerialization` produces report bytes this service cannot
reproduce, and every report signature fails. `canonical.rs` pins the
byte-order rule with tests. The durable fix is for the spec to state a
canonical form; until then, clients should sort by UTF-8 byte order.

## Running locally

```bash
cargo test

# The manifest must name the key you sign with; boot once to learn it.
export AUTHORITY_SIGNING_SEED=$(openssl rand -hex 32)
cp manifest.example.json /tmp/manifest.json
AUTHORITY_MANIFEST_PATH=/tmp/manifest.json AUTHORITY_STORE_PATH=/tmp/authority.sqlite cargo run
# ...read `signingKey` from /health, set it as `operator` in the manifest, restart.
```

## Deploying

See [SKILL.md](SKILL.md).

## Status

Reference implementation. Known limits:

- **Nothing calls `accept-mandate` yet.** The endpoint is implemented
  and tested here, but the interface (`../apple`) does not POST the
  countersigned mandate to the authority, and the iOS client has no
  registration operation. Until that lands, jurisdiction has to be
  seeded by hand — which means the end-to-end consent path is not
  closed, across all three repos.
- **The new-holder path cannot be authenticated here.** A new owner is
  by definition not the mandated identity, so their claim cannot be
  signature-checked. It answers every caller identically — filed or
  not, real case or invented — and records only claims against a ban in
  force. Claims are bounded to eight per case to cap unauthenticated
  storage, but those eight slots are exhaustible by a stranger because
  this service has no ownership proof or claim-resolution lifecycle.
  That is an accepted limitation, not a complete anti-burning remedy.
  Real attestation that a device changed hands needs the interface,
  which holds the device key.

- **Prompt delivery is detached and not single-flight.** Case openings,
  decisions, and the sweep may drain the same backlog concurrently.
  The interface store is idempotent, but duplicate attempts and
  piled-up timeouts remain an accepted operational limitation of this
  reference service.

- **The manifest's `appellate` is published but not routed to.** An
  appeal is reviewed by this authority's own moderator in the panel; a
  deployment declaring an external appellate must forward to it by
  hand. For a class with a `permanent` term the contract *requires* an
  external appellate, so that gap matters most exactly where the
  sanction is heaviest.
- **Triage classifies text.** Evidence that is an image or a video is
  not scored; those cases come back inconclusive and wait for a human,
  which is the safe direction but leaves the most serious classes least
  automated.
- **Notices are returned to the reporter's call and stored, not pushed
  to the accused.** Serving them is the interface's job (§5.5), and it
  reads them from the gate check.
- **Confidentiality is coarse.** `query-status` withholds the
  reporter's identity, but there is no per-authority confidentiality
  policy engine, and no anonymized statistics publication yet — both
  are manifest promises this implementation does not keep on its own.
