# Transparency

## What gets published

Non-content aggregates, on a schedule to be set before this authority
takes its first mandate:

- reports received, and how many were refused at intake;
- cases opened, by class;
- outcomes: banned, dismissed on the record, dismissed by default at
  the decision deadline;
- appeals filed, upheld, and reversed;
- new-holder claims filed, refused, and granted;
- how many cases were decided by a person and how many by a
  classifier — currently all of the former, since no classifier runs.

Counts only. Nothing identifying a reporter, an accused, or a device.

## The number that matters most

**Dismissed by default** — cases where this authority failed to decide
before the deadline. Those are not moderation outcomes, they are this
service failing to work, and reporting them alongside the others is
what keeps that visible rather than looking like leniency.

## What you can check without waiting for a report

- `GET /manifest.json` returns the exact bytes your mandate pinned.
  Hash them yourself.
- Every verdict is signed by the key the manifest names as `operator`,
  and states the class, the reasoning reference, and when it was
  decided.
- `GET /v1/cases/:id/status`, proved with the key that made you a party
  to the case, returns its stage, deadlines, disposition, and history.
  A stranger gets the same answer as for a case that does not exist —
  a distinguishable refusal would confirm that a named person is under
  investigation.

## This document is not yet complete

The schedule and the first report are still to be set. Until they are,
the accountability that exists is the per-case kind above, which is
checkable today, rather than the aggregate kind, which is not.
