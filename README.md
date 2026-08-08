# onym-moderation

Reference implementations of the Onym **moderation seat** — the
institutional service that receives signed reports of prohibited
content, runs a case with notice and a response window, and issues
signed verdicts that a conforming interface executes as durable
per-device marks.

The governing contract lives in
[onym-system/moderation](https://github.com/onymchat/onym-system/tree/main/moderation):
`Moderation.md` is the technology-neutral boundary, with one
implementation profile per device-mark platform.

## Layout

| Directory | What it implements | Owner in the contract |
|---|---|---|
| [`apple/`](apple) | The enforcement backend for the Apple DeviceCheck profile | Interface vendor |

`apple/` is the interface vendor's half: it holds the DeviceCheck key
and therefore the only write path to any device's bits. It executes
verdicts; it does not decide them.

The **authority's** half — intake, cases, notices, verdict signing — is
a separate service, owned by a separate operator, and is not in this
repo yet. That separation is the point of the seat rather than an
accident of layout: an authority that could write marks, or an
interface that could originate verdicts, would collapse exactly the
power this contract splits.

Android's sibling profile (Play Integrity device recall) would live
here too, as `android/`, and deliberately shares the enforcement
backend's requirements so one backend can serve both.

## Why a reference implementation

Both profile documents close with the same gap: *"No current Onym
repository implements any part of this profile."* Everything in them
was requirement, not behavior. This repo is where that stops being
true — and where a second interface vendor can read working code for
the parts the prose leaves to judgment (what a gate check answers when
Apple refuses a token, what the write log has to contain to be worth
auditing, how a verdict's derived deadlines are checked against the
terms a user consented to).
