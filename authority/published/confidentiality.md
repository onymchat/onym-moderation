# Confidentiality and retention

## Who sees what

**The reporter's identity is never disclosed to the accused** without
the reporter's consent, unless law requires it. It is visible to this
authority, because weighing a report means knowing who filed it. It is
absent from case status, from the notice, and from the moderator panel
by construction rather than by policy.

**The accused receives enough to answer.** The class, the intake basis,
the disclosed evidence, both deadlines, the policy digest, and — where
one was used — the model profile, the document the model read and its
final output.

Two things are withheld from the accused's copy even so, because the
reporter wrote them: the reporter's own account of the material, and
any part of a model's output that quotes it back. Withholding the first
and handing over the second would close one channel and leave the one
beside it open.

**A model's private reasoning is not retained.** Where a model emits a
chain-of-thought block, it is stripped before storage. It is neither a
verdict reason nor evidence.

## Where classification happens

**On this host.** Case evidence is content a recipient disclosed for
adjudication; sending it to a third party's API would be a further
disclosure, and under the reference policy a change requiring fresh
consent. The service refuses to start if its classifier endpoint is not
on this machine, and refuses to send a case document to a host it has
not confirmed is local.

At present no classifier runs at all: every case is decided by a
person. Introducing one means publishing a new manifest that names it,
and taking fresh mandates against that manifest — it cannot be turned
on underneath an existing consent.

## Retention

**No deletion schedule is published, because none is kept.**

This is deliberate and it is the uncomfortable answer. A period named
here that the implementation did not honour would be worse than naming
none: you would be relying on a deletion that never happens. Nothing in
this service deletes case material on a timer today, so nothing here
promises that it does.

What is held, and why it cannot simply be dropped:

- **Signed mandates and verdicts** — needed to validate or clear a live
  mark. A device's marks are two bits with no explanation attached; the
  record here is the only thing that says what they mean, and losing it
  would leave someone marked with no way to show why or to have it
  lifted.
- **Case material** — reports, disclosed evidence, responses, appeals,
  and final model outputs — for as long as intake, the case, and any
  appeal require.
- **Non-content audit records** — enough to answer "did this happen,
  and when".

Case material is **not sold, not used for advertising, and not used to
train a model.**

If a retention period is committed to in future, it will be built
first and published second.

## Bounds

Storage is bounded per case, so the record cannot be used as a dumping
ground: at most 32 responses and 32 appeal filings per case, 8 notices,
8 new-holder claims, and 16 KiB per statement.
