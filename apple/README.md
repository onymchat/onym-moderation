# onym-moderation / apple

Enforcement backend for the Onym moderation seat, Apple DeviceCheck
profile. Reference implementation of
[`Moderation-DeviceCheck.md`](https://github.com/onymchat/onym-system/blob/main/moderation/Moderation-DeviceCheck.md),
whose §8 gap 8 ("no Onym implementation exists yet") this is meant to
close.

## What it is, and what it deliberately is not

The moderation seat has two halves, owned by different parties on
purpose:

| | Owner | Holds | This repo |
|---|---|---|---|
| **Moderation authority** | Independent operator | Verdict signing keys, case procedure, judgment | no |
| **Enforcement backend** | Interface vendor | Apple DeviceCheck key — the only write path to the bits | **yes** |

That split is the contract's load-bearing separation: *the authority's
key can sign verdicts; it can never write marks. The interface can
write marks; it can never originate them* (Moderation.md §5.7).

So this service decides nothing. It receives signed verdicts, checks
their **shape** mechanically — never their wisdom — and executes the
ones that conform. A verdict missing its reasoning, naming a class
outside the mandate, or carrying an expiry longer than the term the
user consented to is refused, no matter who signed it.

## The two bits

Apple stores exactly two bits per device, per developer account:

| Bit | Mark | Set by | Cleared by |
|---|---|---|---|
| `bit0` | `case-open` | a valid interim `open-case` verdict | dismissal, superseding ban, decision-deadline default |
| `bit1` | `banned` | a valid ban verdict, at or after its `executeAfter` | expiry, reversal, new-holder appeal |

Everything else — which verdict, which case, until when — lives in this
service's store. The bits are a cache of its conclusions, which is why
losing `/data` loses the meaning while Apple keeps the values.

## Endpoints

Three serve the iOS client's `EnforcementBackendClient` seam:

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/enroll` | First-session enrollment → the vendor-local `deviceBinding` a mandate carries |
| `POST` | `/v1/mandates/countersign` | Interface countersignature over the mandate the user signed |
| `POST` | `/v1/gate-check` | Read the bits, reconcile, answer `clear` / `caseOpen` / `banned` / `checkRequired` |

One receives verdicts from the designated authority:

| `POST` | `/v1/verdicts` | Validate mechanically, store, execute or queue |

Two are for operators and auditors:

| `GET` | `/health` | DeviceCheck configured? enforcement on? interface public key |
| `GET` | `/v1/write-log` | The append-only write log and whether its hash chain verifies |

## Invariants it actually enforces

These are the ones worth checking a reimplementation against:

- **A request with no device token, or one Apple refuses to validate,
  never answers `clear`.** There is no way to know a device is clean
  without asking Apple, and guessing permissively is the bypass the
  whole seat exists to prevent. The iOS client's stub is allowed to
  answer `clear` to a nil token so simulators stay developable; a real
  backend is not, and this one does not.
- **Marks move only on verdicts, and defaults only ever clear.** Expiry,
  dismissal, and reversal can clear a mark; nothing but a validated
  verdict sets one. There is no administrative endpoint that writes
  bits, by design.
- **The sanction is bounded by the consented terms.** `appealDeadline`
  must equal `decidedAt +` the class's `appealWindow`, and a duration
  ban's expiry must equal execution `+` its `banTerm` (§5.6 constraint
  3) — so a P90D class cannot carry a ten-year expiry, and an authority
  cannot collapse the appeal window to zero.
- **Countersigning returns only a signature.** Handing back a whole
  mandate would let this service alter a consented field behind the
  user's signature; the client appends what we return to its own copy.
- **Every `update_two_bits` is logged against the verdict that
  authorized it**, in a hash-chained table, so a deleted or doctored
  entry is detectable. That log plus an audit-seat attestation is this
  profile's substitute for a platform-level proof that the vendor wrote
  faithfully (§8 gap 3) — until an auditor actually attests a
  deployment, it remains a paper control.

## Cross-implementation agreement

The signed session payloads are reconstructed here from exactly the
fields the client transmits. `src/payload.rs` carries fixtures produced
by running the **iOS client's own `SignedSessionPayload`** — not a
retyping of it — so a drift that would reject every real signature
fails a test instead. Regenerate those fixtures from Swift if the
client's format ever changes.

The same care applies to canonical signing bytes (`src/canonical.rs`):
signature fields are removed structurally, never by string surgery,
which is forgeable. Both sides remain PROVISIONAL in the sense the spec
is — no canonical JSON form is specified, so the agreement is by
construction between these two implementations.

## Running locally

```bash
cargo test
MODERATION_INTERFACE_SIGNING_SEED=$(openssl rand -hex 32) \
MODERATION_STORE_PATH=/tmp/moderation.sqlite \
cargo run
curl -s localhost:8080/health
```

Without DeviceCheck credentials the gate answers `checkRequired` for
everyone — degraded toward blocking, never toward unmoderated
operation.

## Deploying

See [SKILL.md](SKILL.md), which is written for an agent (or a person)
with a DigitalOcean API key. Short version:

```bash
cp .env.example .env && $EDITOR .env
cp /path/to/AuthKey_XXXXXXXXXX.p8 secrets/devicecheck.p8
./deploy/digitalocean/deploy.sh
```

## Submitting a verdict

The authority POSTs an envelope, not a bare verdict:

```json
{
  "verdict": { "...": "the signed verdict object" },
  "consentedManifest": "<base64 of the manifest's exact bytes>"
}
```

The manifest travels as **exact bytes** because the mandate pins their
SHA-256, and only the original bytes reproduce that hash. That binding
is what makes the submission safe to trust: both the class terms the
verdict is measured against *and* the operator key its signature is
checked against come from the manifest the **user** consented to, not
from the request. Supplying a substituted manifest fails the hash
check; supplying the real one means signing with the real operator key
or not at all.

## Status

Reference implementation. One thing is **not** production-ready without
a decision from the operator:

- `MODERATION_ENFORCE_SIGNATURES` defaults to `false`, so verdicts with
  unverifiable authority signatures are accepted. That is for the
  pre-launch world where no authority publishes a signing key yet. Set
  it `true` before anyone can reach the endpoint.

The verdict endpoint and the write log both fail closed: without
`MODERATION_AUTHORITY_TOKEN` the former refuses everything (unless
`MODERATION_ALLOW_UNAUTHENTICATED_AUTHORITY=true` is set deliberately),
and without `MODERATION_AUDIT_TOKEN` the latter is closed entirely,
since it names every device binding, verdict, and mark transition.

### A limit worth stating plainly

DeviceCheck tokens are ephemeral and unlinkable by design, so this
service cannot tell one device from another across sessions. It
validates the token with Apple at enrollment, which proves a real
device was there, but it cannot prove the *same* device returns later.

The consequence is handled rather than hidden: when a banned identity
presents a device whose bits are clean and the ban has already been
written somewhere, the service refuses the identity but leaves that
device's bits alone. Branding it would mark hardware the verdict never
named — quite possibly a new owner's. That follows the contract's own
division, where the identity refusal covers every surface while device
marks reach only the devices a verdict names (§5.3 constraint 4).
