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

**A schedule is published and enforced.** It has its own document —
[retention](./retention.md) — because the periods are named in the
manifest and therefore pinned by your mandate.

In short: an unreported upload lasts a day, a case's images last thirty
days past the end of the case, the case record and its audit trail last
400 days past the same point, and the mandate and verdicts behind a
sanction last 400 days past the moment the last mark they justify ends —
never while one is in force.

An earlier version of this document said no schedule was published
because none was kept, and undertook that if one were ever committed to
it would be built first and published second. That is what happened. The
periods are enforced by a sweep that compares wall-clock times, so they
survive a restart, and it logs what it removed.

What is held regardless of any timer, and why it cannot simply be
dropped:

- **Signed mandates and verdicts, while a mark is live** — a device's
  marks are two bits with no explanation attached; the record here is the
  only thing that says what they mean, and losing it would leave someone
  marked with no way to show why or to have it lifted. A permanent ban
  means a permanent record.
- **That a case existed** — its class and how it ended, with no
  disclosed content. This is what makes the transparency counts
  answerable.
- **Material under a preservation duty** — where law specifically
  requires it. A preservation hold outranks every period above, and its
  release date is fixed when it is placed so a later, shorter period
  cannot cut it short. See [lawful reporting](./lawful-reporting.md).

Case material is **not sold, not used for advertising, and not used to
train a model.**

This document speaks for what this service stores. Backups, if an
operator keeps them, are the operator's to account for.

## Bounds

Storage is bounded per case, so the record cannot be used as a dumping
ground: at most 32 responses and 32 appeal filings per case, 8 notices,
8 new-holder claims, and 16 KiB per statement.
