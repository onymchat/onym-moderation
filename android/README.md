# onym-moderation-android

Enforcement backend for the Onym moderation seat — the **Google Play
Integrity device recall** profile
(`onym:moderation-enforcement-profile:google-device-recall-v1`), the
Android sibling of [`apple/`](../apple/README.md).

Spec: `onym-system/moderation/Moderation-Device-Recall.md` (the profile)
over `Moderation.md` (the abstract contract). The two backends agree by
bytes, not by shared libraries: `canonical.rs`, `countersigning.rs`,
`verdict.rs`, and `util.rs` are verbatim copies whose tests are the
agreement pins.

## The boundary

This service is the *interface vendor's* side of the contract, not the
moderation authority's. It holds the service-account key of the Google
Cloud project linked in the Play Console, and therefore holds the only
possible write path to the per-device recall values. It decides
nothing: an authority signs verdicts, this validates their shape
mechanically and executes the well-formed ones.

The marks:

| Recall value | Abstract mark |
|---|---|
| `bitFirst` | `case-open` |
| `bitSecond` | `banned` |
| `bitThird` | reserved — **never written**; `RecallChanges` has no field for it |

Writes specify only the values a transition changes (unspecified values
are unchanged at Google), and every `deviceRecall:write` — accepted or
refused — lands on the hash-chained write log with the verdict (or
clearing rule) that authorized it and the exact fields the request
named (`fields_written`).

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness + configuration surface |
| `POST` | `/v1/challenge` | `{purpose: "enroll"\|"gate"}` → single-use challenge for the session's signed payload / `requestHash` |
| `POST` | `/v1/enroll` | `{userKey, timestamp, challenge, integrityToken, signature}` → `{deviceBinding}` |
| `POST` | `/v1/mandates/countersign` | exact user-signed mandate bytes → `{signature}` (never a rebuilt mandate) |
| `POST` | `/v1/gate-check` | `{userKey, mandateRef?, timestamp, challenge, integrityToken, signature}` → gate result |
| `POST` | `/v1/recover` | **501** — reserved; ban/check-required responses carry the authority's contact and new-holder routes instead of a silent brick |
| `POST` | `/v1/verdicts` | authority bearer token; `{verdict, consentedManifest}` → `{verdictRef, status}` |
| `GET` | `/v1/write-log` | audit bearer token; the hash-chained log + chain verification |

Gate results are internally tagged (`{"status":"clear"}`,
`{"status":"caseOpen","notices":[…]}`, `{"status":"banned","ban":{…}}`,
`{"status":"checkRequired","reason":"…"}`) — the Android profile's own
schema, not the Swift-Codable `_0` shape the iOS service speaks.

## A session, end to end

1. The app fetches a challenge, builds the length-prefixed signed
   payload (`fixtures/README.md` — **normative**, generated here, the
   Kotlin client reproduces it), signs it with the identity key, and
   passes `base64url-nopad(SHA-256(payload))` to Play Integrity's
   `setRequestHash`.
2. The backend verifies the identity signature over the recomputed
   payload, claims the session signature (single-use, bounded skew) and
   the challenge (single-use, purpose-bound, TTL'd), then decodes the
   token through Google.
3. The five-condition classifier (spec §5.2) runs before any recall
   value is read: fresh matching `requestDetails` incl. `requestHash`;
   `PLAY_RECOGNIZED` with an expected signing-cert digest; `LICENSED`;
   `MEETS_DEVICE_INTEGRITY`; the `deviceRecall` object present. Any
   failure is `checkRequired`, never clean. A present-but-empty recall
   object *with every prerequisite passing* is the profile's clean
   never-written state — the irreducible §8-gap-6 ambiguity, monitored
   via the `recall_empty_result` tracing event.
4. Reconciliation folds the stored verdicts into intended marks, writes
   only the changed values (skipping rewrites inside
   `MODERATION_PROPAGATION_GRACE_SECS` of an accepted write — Google
   documents up to 30 s of read lag), and answers.

An executed ban meeting clean values is a *different device* presenting
the same identity: the identity is refused, the device never branded —
integrity tokens are request artifacts, not device identifiers.

## Configuration

See `.env.example`. Without `MODERATION_PLAY_*` credentials the service
still countersigns and stores verdicts, but every gate check answers
`checkRequired` — degraded toward blocking, never toward unmoderated
operation. Production checklist: `MODERATION_ENFORCE_SIGNATURES=true`,
`MODERATION_AUTHORITY_TOKEN` set, `MODERATION_AUDIT_TOKEN` set.

One-time Google setup:

1. Play Console: enroll the app in Play Integrity, request **device
   recall beta** access and opt in, link the Cloud project.
2. Cloud console: enable the Play Integrity API; create a service
   account with the Play Integrity API role; download its JSON key to
   `secrets/play-sa.json`.
3. Record the app's Play App Signing certificate SHA-256 digest in
   `MODERATION_PLAY_CERT_SHA256_DIGESTS`, Google's spelling.

## Operational rules the code cannot check

- **Device recall values are Play-developer-account-wide** (spec §1,
  §8 gap 2): every app in the account reads and can write the same
  three values. The account must be dedicated to interfaces sharing
  this exact bit contract. An app transfer abandons the marks.
- **Retention is a three-year lease** refreshed by reads/writes (§8
  gap 3): a device absent longer can return clean. Backend identity
  refusal persists regardless.
- The exact `deviceRecall:write` request field names have no Google
  sandbox to test against; re-verify them against the live API on
  first deploy (see the NOTE in `src/play_integrity.rs`).

## Deferred: `/v1/recover`

Device recovery (moderator-issued grants moving a case's record to a
new holder's enrollment, and case-free unbans) is implemented in
`apple/` and deliberately not yet here; the endpoint answers 501 and
the refusal surfaces carry the authority's contact/new-holder routes,
which keeps the minimal vertical conforming (spec §5.2 item 3). A
banned device whose enrollment does not survive has no machine path
back until this lands — re-adding it must also reintroduce `apple/`'s
`binding_for_ingest` routing at verdict ingest.

## Deploy

`deploy/digitalocean/deploy.sh`, mirroring `apple/` (Caddy TLS, compose,
named volume `moderation-data` — back it up: the recall values alone
are uninterpretable without the verdict store). Default host:
`moderation-android.onym.app`. The authority routes verdicts for
mandates naming `onym:component:onym-android` here (see
`authority/` interface routing), and adds this service's countersigning
key (from `/health`) to its `AUTHORITY_INTERFACE_KEY` list.
