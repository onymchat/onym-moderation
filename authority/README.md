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

The web panel also exposes the initial human decision for an open case.
Set `AUTHORITY_TRIAGE_MODE=off` when humans should decide every case. For
local or staging QA only, `AUTHORITY_QA_ALLOW_EARLY_BAN=true` lets a human
exercise the ban form before the consented response window closes. Never set
that flag on a public authority; it is deliberately ignored for automated
decisions and defaults to false.

With triage enabled, an `AUTHORITY_TRIAGE_URL` that is not on this host
is a **startup failure**, not a warning — and where the name cannot be
resolved yet, a refusal at the first case rather than a pass. Case
evidence is content a reporter disclosed for adjudication; a log line
about having sent it to a third party arrives after the disclosure has
happened.

**A new-holder claim is tracked in its own field, not the appeal's.**
It does not say the verdict was wrong — it says the device changed
hands and the mark is punishing someone the case was never about. Both
reach a human and the panel says which it is showing. They are separate
fields because the path is unauthenticated: sharing one let a claim
swallow a pending appeal, and let anyone knowing a case id lock the
accused out of §12 relief entirely.

A reversal answers whatever was pending, wherever it came from — the
JSON API and the panel reach the same code, so a reversal cannot leave
an appeal queued for a moderator to "uphold" afterwards. Reversing a
ban nobody appealed is the authority correcting itself, and is recorded
as that rather than as an appeal outcome.

Whatever the mode, three things do not change:

- **A ban waits for the response window** — and so does the assessment
  itself. A case is not shown to a model until the accused's consented
  window has elapsed, because the document the model judges must be the
  completed one, including whatever they filed in their own defence.
  Answering early does not bring it forward: the window is time they
  were promised, not one chance to speak. The ban guard lives in
  `decisions.rs`, where all three callers inherit it, so a classifier's
  certainty cannot shorten it either.
- **A ban after the decision deadline is refused.** By then the case is
  already dismissed by default, and a decider must not win that race
  against the sweep.
- **A dismissal lands immediately.** It is not a sanction, and making
  someone wait for one helps nobody.
- **Undecided is still dismissal.** If the model is down and no human
  arrives, the case hits its decision deadline and dismisses itself.

## Which model? Any of them.

Nothing in this service is tied to a particular vendor. A **model
profile** is a prompt template plus an output adapter, and everything
model-specific — prompt, output format, thresholds, category mapping,
what counts as invalid — lives in one. Six published profiles ship
built in:

| `AUTHORITY_TRIAGE_PROFILE` | Model | Decides by |
|---|---|---|
| `shieldstral-3b` | `mistralai/Shieldstral-1.0-3B` | first-token score, 0.90 / 0.20 |
| `gpt-oss-safeguard-20b` | `openai/gpt-oss-safeguard-20b` | binary `1` / `0` |
| `qwen3guard-8b` | `Qwen/Qwen3Guard-Gen-8B` | native taxonomy |
| `nemotron-3.5-content-safety-4b` | `nvidia/Nemotron-3.5-Content-Safety` | `User Safety:` label |
| `llama-guard-4-12b` | `meta-llama/Llama-Guard-4-12B` | native hazard codes |
| `shieldgemma-9b` | `google/shieldgemma-9b` | first-token score, 0.90 / 0.20 |

Each corresponds to a published profile document in
[`../authorities/`](../authorities/), and each pins a model repository
*and revision*: a different revision is a different decision-maker, so
it is part of the terms rather than a deployment detail.

For anything else, write the same shape as JSON and point
`AUTHORITY_TRIAGE_PROFILE_PATH` at it — no code change, because there
is no code that knows about any particular model:

```json
{
  "id": "house-classifier-v3",
  "displayName": "In-house classifier",
  "profileDigest": "<sha256 of this document's execution bytes — see below>",
  "policyDigest": "<sha256 of the policy it incorporates>",
  "repository": "example-org/house-classifier",
  "revision": "<commit>",
  "servedModel": "house-classifier",
  "supportsImages": false,
  "maxInputTokens": 8192,
  "nativeTaxonomy": false,
  "prompt": {
    "system": "Apply this rule and answer VIOLATION or CLEAR:\n{rule}",
    "user": "{document}",
    "usesCanonicalRule": true
  },
  "adapter": { "kind": "exactOutput", "ban": "VIOLATION", "dismiss": "CLEAR" }
}
```

Four adapter kinds cover the published profiles: `firstTokenScore`,
`exactOutput`, `labelLine`, and `nativeTaxonomy`.

### Computing `profileDigest`

It names the document's **execution bytes**: every field except
`profileDigest` itself, re-serialized with sorted keys. Those are the
bytes that decide cases, and excluding the digest field is what makes
the value constructible — a document cannot state a hash of itself that
includes the statement.

```bash
jq -cSj 'del(.profileDigest)' profile.json | shasum -a 256
```

Write the result into `profileDigest` and the document still hashes to
it. The service recomputes this at boot and refuses to start if the
declared value disagrees, so editing a prompt, threshold, adapter or
revision without recomputing is a startup failure rather than a live
deployment judging old mandates under replacement terms. Leaving the
field empty means the computed value is adopted with nothing to check
it against — fine while you are iterating, not something to ship, and
not something to name in a manifest.

Built-in profiles are the exception: their digest names the published
prose document in [`../authorities/`](../authorities/), which is what
users were shown, and a test pins each constant to its file.

### The manifest names the profile, and the case binds to it

A manifest may declare `modelProfile` — the profile's id and the
SHA-256 of its published document. When it does, two things follow: the
service refuses to start under any other profile, and a case is only
decided under the profile *its own consented manifest* names. Without
that second check an operator could change an environment variable and
have a live case decided by a different model, prompt or adapter than
its accused agreed to, with the assessment recording the substitution
after the fact as though it had always been the terms.

A manifest that declares none gets a warning at boot: nothing binds
that deployment's classifier to anything a user consented to.

### A profile is consented policy, not configuration

There is no `AUTHORITY_TRIAGE_BAN_THRESHOLD`, and that absence is
deliberate. The reference policy requires an authority to publish its
prompt, thresholds, mapping and invalid-output behaviour *before*
consent, and says those values "are consented policy, not mutable
server configuration". An operator who could retune the ban threshold
between two cases would be deciding the second one under terms nobody
agreed to. The only field a deployment overrides is
`AUTHORITY_TRIAGE_SERVED_MODEL` — what your inference server happens to
call the loaded model, which is nobody's consent.

There is also no default profile. Which model decides a case is a term
users agree to; inheriting one silently is not a thing this service
will do.

## Three outcomes, and the third one matters most

Every adapter returns ban, dismiss, or **no decision**. Output that is
invalid, incomplete, in an ambiguous score band, or in a category this
class does not map to is *not* a verdict:

- the case stays open, and the sweep retries it;
- if no valid decision ever lands, the decision deadline dismisses it.

The failure mode this exists to prevent: unrecognised response → no
categories found → score zero → dismiss, which would turn every model
outage into a mass acquittal. Its mirror image would be far worse. A
test asserts that none of the six profiles turns a timeout page, a
refusal, or an empty body into a verdict.

Only score-producing profiles record a score. A profile whose model
emits a label gets **no** invented confidence number — a fabricated
`0.5` sitting in a case file reads as evidence to whoever opens it
later.

## Category mapping, for profiles that use one

A model's native categories are not violation classes. `Violent` is not
an offence; `credible-violence` is, and only the manifest says so. The
native-taxonomy profiles publish that correspondence, along with the
mismatch it carries: `S12` does not establish that a transmission was
unsolicited, and `Sexual Content or Sexual Acts` does not establish
that anyone was under 18. That is why those profiles disclose the
mismatch at consent time and why a human applies the *narrower*
canonical rule on appeal.

Only the code mapped to the case's class counts. A model flagging some
other category has said nothing about the class the accused consented
to be judged under, and the outcome is no decision — never a ban.

## The model runs on this host

`AUTHORITY_TRIAGE_URL` defaults to a sibling container, and with triage
enabled the service **refuses to start** if it points anywhere else. A
dotless name is resolved and its addresses checked, because a DNS
search domain can point `moderation-model` at someone else's machine.

One case is deferred rather than refused: a name that does not resolve
*at all* is accepted at boot, because the model container may have
started second and refusing to come up over that is its own failure.
The check is then paid before the first request that would carry
evidence — a name that still does not resolve, or resolves off-box by
then, fails the assessment instead of the boot. So triage never sends a
case document to a host it has not confirmed is local; it may just tell
you at the first case rather than at startup.

Case evidence is content a recipient disclosed *for adjudication*.
Sending it to a third party's API is a further disclosure — one the
manifest's confidentiality policy would have to declare (§8 obligation
6), and which the reference policy makes a change requiring fresh
consent. Keeping inference local means the disclosed content stays with
the operator who was consented to.

The client speaks the OpenAI-compatible chat-completions shape that
llama.cpp, vLLM, Ollama and TGI all serve. Score-based profiles
additionally need `logprobs` and `top_logprobs`; the service says so at
boot, because otherwise the symptom is every case quietly reaching no
decision. What can serve a given model locally depends on your
licensing, so the compose file leaves the image to the operator rather
than pinning one this project cannot verify.

## What the model is shown

The case document is the reference policy's §4.1 shape, in order:
`CLASS`, `REPORTED MATERIAL`, `REPORT CONTEXT`, `ACCUSED RESPONSE` —
the last being the literal `NONE` when nobody answered, because silence
is a fact about the case rather than an absence in the prompt.

It is built **after the response window closes**, never on arrival.
Assessing earlier would ask the model about a document the accused had
not finished answering, and then decide the case on that reading. The
sweep is the only thing that starts an assessment; there is no
classify-on-arrival path, because there is nothing for one to do.

The sweep spaces retries out and gives up eventually: a model that
could not read a case a moment ago is unlikely to read it thirty
seconds later, and a case it will never read should end at its decision
deadline — dismissed — rather than being retried until then. A failed
round-trip counts as an attempt, which is the failure the backoff
exists for; recording only the model's *readable* answers would have
left an unreachable model re-hit for every due case, every tick.

Assessment runs in its own task, on its own clock. Deadlines and
delivery never wait behind it: 25 cases awaited in turn at a two-minute
timeout is a tick far longer than the interval, and "undecided is
dismissal" is the invariant that must not queue behind an unrelated
inference.

Every untrusted field is fenced, and text that would close its own
fence is defanged on the way in — visibly, so a reviewer can see the
author wrote something fence-shaped rather than wonder why the quoted
evidence differs. This is not a claim that prompt injection is solved;
the profiles say plainly that it is not. It removes the cheapest
version.

The document itself is kept, not only its digest — an appeal reviewer
applying the narrower canonical rule cannot do it from a hash, and for
the native-taxonomy profiles that review is the whole remedy. The panel
renders it alongside the rule to apply, and `query-status` returns it
to the accused, so the content address in a verdict's `reasoning` is
something a party can actually resolve.

**The model's stored output carries no reasoning.** A profile running
with thinking enabled puts the whole block inside its final message,
and the reference policy is explicit that private chain-of-thought "is
neither a verdict reason nor evidence and need not be retained or
disclosed". It is stripped before storage, leaving a visible marker.
The adapter still evaluates the full output — an unclosed reasoning
block is how it detects a truncated generation.

**The accused's copy withholds `REPORT CONTEXT`.** That field is the
reporter writing in their own words, and "he sent it after I asked him
to stop" identifies them completely in a two-person conversation — a
case several people reported would hand over all of them. The
withholding is visible rather than silent: an accused shown a gap can
ask about it, one shown a seamless document does not know there is
anything to ask for. Moderators see the whole of it, because the
authority is allowed to.

The same withholding applies to the **model's own output**, which can
quote what it was shown — ShieldGemma's prompt asks it to "walk
through step by step", and Nemotron reasons in the open. Redacting the
document and then serving the model's prose beside it would close one
channel and leave the one next to it open.

What this catches is verbatim quotation, which is the realistic case.
It cannot catch a paraphrase, and nothing at this layer can: a model
that restates the reporter's account in its own words has still said
it. Nor does it catch an account shorter than three characters, which
is not a meaningful string to match on. That residue is a reason to prefer the label-producing profiles
where a reporter's safety is the dominant concern — `qwen3guard-8b`,
`llama-guard-4-12b`, `gpt-oss-safeguard-20b` and `shieldstral-3b` all
emit a bounded label rather than prose.

Its SHA-256 goes on the assessment, and is re-checked after inference:
a reading of a document that changed while the model held it — a late
response, another report joining the case — decides nothing and the
case is reassessed. Otherwise the response the accused filed would have
had no bearing on the decision that banned them.

A stale reading is **not** charged to the case's attempt budget. The
model answered and the case was fine; the record simply moved
underneath it. Charging it would let the accused spend the budget
themselves — a late response is accepted for as long as the case is
open, so landing one during each inference would exhaust the attempts
and run the case to its decision deadline, where it dismisses by
default. A guard against deciding on unanswered evidence would have
become a way to guarantee acquittal. So do the profile digest, policy
digest, model revision, the raw final output, and how many evidence
items and responses were in the document — "did it see my reply?" has a
recorded answer rather than an inferred one. Private chain-of-thought
is not stored: it is neither a verdict reason nor evidence.

## The moderator panel

Server-rendered at `/admin`, behind `AUTHORITY_ADMIN_TOKEN` and a
session cookie (`HttpOnly`, `SameSite=Strict`, `Secure`).

Besides the case queues below, `/admin/recovery` holds **device
recovery claims**: a person holding a marked device whose enrolled
identity no longer resolves — a reinstall, or hardware that changed
hands — files a claim (`POST /v1/recovery-claims`) with a real contact
and their account of how they hold the device. There is deliberately
no self-serve path. A moderator verifies the holder through the
contact and either refuses or issues a **recovery grant**: a document
signed by the operator key, naming the case and the claimant's new
identity, single-use, lapsing after 30 days. The claimant's app polls
`GET /v1/recovery-claims/:id` (signed by the same key) and redeems the
grant at the interface, which moves the case's verdict record to the
new identity and reconciles — and refuses the grant while any record
still bans the device, so a grant can never override a standing ban.

It has **two** queues, and which one is the job depends on whether a
classifier is running:

- **Awaiting decision** — open cases with no verdict yet, soonest
  decision deadline first, with the time remaining shown and anything
  inside two days marked. Under autonomous triage this holds the cases
  the model declined to decide. With triage off it is the entire
  workload, and it has a clock: a case nobody decides is dismissed by
  default at its deadline (§3.5), which is safe for the accused and
  silent for everyone else. It also says whether each response window
  has closed, because a ban before it has is refused — worth knowing
  before opening the file rather than after.
- **Appeals awaiting review** — appeals and new-holder claims.

Recent cases are listed below both for oversight. The page states which
mode it is in rather than assuming: telling a moderator that "triage
decides in the first instance" when no classifier is configured
describes their whole workload as somebody else's problem.

**Something must be able to decide.** Autonomous triage needs neither
token; otherwise a person does, and the only two routes in are
`AUTHORITY_MODERATOR_TOKEN` (the JSON API) and `AUTHORITY_ADMIN_TOKEN`
(this panel). With no classifier and neither token the service refuses
to start, because it would otherwise accept reports, serve notice, run
every window and dismiss every case — an authority that looks healthy
and cannot reach a verdict.

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

A decision that answers a claim — `"reviewed": "appeal"` or
`"new-holder"` — should also carry `"claimRevision"`, the value
`query-status` reported when the claim was read. The decision then
refuses to commit if the claim gained a supplementary filing, or was
answered by another moderator, in between: neither of those moves the
case's own revision, and a pending appeal that has been supplemented is
still `pending`, so nothing else would notice. The panel always sends
it; omitting it decides against whatever the record says at commit
time.

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
