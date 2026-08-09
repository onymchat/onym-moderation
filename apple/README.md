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

That store outlives the container it was created by, so the schema has
an upgrade path rather than assuming a fresh database: `migrate()`
creates the tables and then adds, to a store an earlier build left
behind, whatever columns have been added since. A column omitted from
that second list reaches new deployments only, and the first read that
selects it kills every existing one.

## Endpoints

Four serve the iOS client's `EnforcementBackendClient` seam:

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/enroll` | First-session enrollment → the vendor-local `deviceBinding` a mandate carries |
| `POST` | `/v1/mandates/countersign` | Interface countersignature over the mandate the user signed |
| `POST` | `/v1/gate-check` | Read the bits, reconcile, answer `clear` / `caseOpen` / `banned` / `checkRequired` |
| `POST` | `/v1/recover` | Redeem a moderator-issued recovery grant: re-bind the case's verdict record, then reconcile |

A word on `/v1/recover`, because it answers `checkRequired:
reidentificationRequired` — the state a marked device lands in when
its enrolled identity did not survive a reinstall or a change of
hands. **There is no self-serve unban.** The holder's claim — real
contact and proof of new-holder status — goes to the authority, where
a human moderator decides it (REFERENCE-AUTHORITY-POLICY §6). What the
device presents here is that decision: a recovery grant signed by the
authority's operator key, resolved through the consented manifest the
case's mandate pinned — the same key the case's verdicts verify
against, so redemption introduces no new trust root.

A grant is bound to the identity it names (stolen, it is useless
without that identity's key on the session), presentable only from a
device whose banned bit Apple confirms in the same signed session,
single-use, and lapses after 30 days. If the case's record has cleared
(reversal, expiry), the stored verdicts are re-bound to the grantee's
enrollment and ordinary reconciliation performs the clearing write —
marks still move only on the signed verdicts already on file. If a
record still bans the device — the case's, or the claimant's own —
nothing moves, the grant is not consumed, and the response carries the
authority's declared routes instead.

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

## Countersigning keys, and rotating one

The interface countersigns a mandate to say it witnessed *this user*
consenting to *that authority*. `MODERATION_INTERFACE_SIGNING_SEED` is
the root of those signatures, and its public half is what an authority
puts in its `AUTHORITY_INTERFACE_KEY`.

One key for every authority made rotation all-or-nothing: changing the
seed invalidated every countersignature ever issued, to every
authority, at once — so a key you suspected was compromised was a key
you were stuck with. Keys are now **per authority**, derived from the
root and a per-authority epoch:

```
epoch 0  →  the root seed itself, underived
epoch n  →  SHA-256(domain ‖ root ‖ componentId ‖ 0x00 ‖ n)
```

`MODERATION_INTERFACE_KEY_EPOCHS` sets the epochs, as
`<componentId>=<epoch>` pairs. **An authority you have never rotated
needs no entry**: epoch 0 is the root key, unchanged, so adopting this
costs no coordination with anyone already configured.

### What it does and does not protect

It buys **rotation and revocation** — burning one relationship without
touching the others.

It does **not** contain a compromise, and it would be a mistake to
believe otherwise. The private seed never leaves this process;
authorities receive only public keys, so no authority can leak it. The
realistic compromise is this host, and every derived key lives in the
same memory as the root. That is also why the keys are derived rather
than stored as N independent secrets: N secrets to generate, back up
and not lose, in exchange for containment the design does not provide.

### Rotating

The authority accepts a **list** of interface keys
(`AUTHORITY_INTERFACE_KEY`, comma-separated), and that is what makes a
gapless rotation possible. It holds one key per entry and checks a
countersignature against any of them.

Without that list there is no safe order. The authority would expect
exactly one key, so whichever side moved first, every registration for
that authority would be refused until the other caught up — reversing
the steps only changes which side of the gap you are on.

1. Derive the next epoch's key without deploying it: bump the epoch in a
   scratch environment and read `rotatedInterfaceKeys` from `/health`,
   or compute it offline with the formula above.
2. The authority operator **adds** it to `AUTHORITY_INTERFACE_KEY`
   alongside the current one and restarts. Both now verify.
3. Bump the epoch here and deploy. Countersignatures switch to the new
   key; the old ones already issued still verify, because the authority
   still lists that key.
4. The authority operator drops the old key. Now — and only now — do
   mandates countersigned under the old epoch stop verifying.

Step 4 is the irreversible one, and it is the point: it is what burns a
key you no longer trust. Everything before it is reversible.

`/health` reports the root key as `interfaceKey` and every rotated
authority under `rotatedInterfaceKeys`. An authority that has never
been rotated has no entry there and uses `interfaceKey` — which is why
the authority-side docs tell operators to check for their own entry
first rather than reading `interfaceKey` blindly.

### If the component id is wrong

`MODERATION_INTERFACE_KEY_EPOCHS` validates the shape of an id, not its
existence — there is no allowlist here, deliberately, since which
authority a user trusts is the user's business. So
`onym:component:autority=1` parses cleanly and leaves the real
authority on epoch 0, with the same symptom as a botched rotation:
registrations refused with a signature error rather than a
configuration one.

The boot log names every configured id beside the key it produced.
Check it against what the mandates actually carry.

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
