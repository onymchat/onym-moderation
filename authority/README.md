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
  speak. Joined evidence produces another signed notice and restarts
  both the response and decision windows; the latest notice must reach
  the interface before a ban can issue. A ban is also refused once the
  decision deadline has passed, since by then the case is already
  dismissed by default. The case-open mark is the only pre-verdict effect.
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

- **Appeals are recorded, not adjudicated.** Filing an appeal logs it
  and notifies; a human then decides via `decide` with `reverse`. The
  manifest's `appellate` is published but this service does not route
  to an external appellate automatically.
- **Notices are returned to the reporter's call and stored, not pushed
  to the accused.** Serving them is the interface's job (§5.5), and it
  reads them from the gate check.
- **Confidentiality is coarse.** `query-status` withholds the
  reporter's identity, but there is no per-authority confidentiality
  policy engine, and no anonymized statistics publication yet — both
  are manifest promises this implementation does not keep on its own.
