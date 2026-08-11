# Retention schedule

This document is the schedule this authority actually applies. It is
named by the manifest, so its address is inside the bytes your mandate
pins: the periods below cannot be changed under an existing consent. A
different schedule means a new manifest and a fresh agreement.

The previous version of this authority's terms published no schedule at
all, on the grounds that a period nobody enforced would be worse than
naming none. That reasoning has not changed. What changed is that the
periods are now built, which is the order it was promised in.

## What a period means

Every period is a **tail measured from the moment the thing it belongs
to has finished** — not a lifetime from when it arrived. "P30D" against
case media means thirty days after the case is over, not thirty days
after the photo was sent.

| What | Kept for | Measured from |
|---|---|---|
| An upload no report ever named | 1 day | the upload |
| A case's images | 30 days | the later of the case's appeal and decision deadlines |
| A case's record — reports, responses, the document a model read, its output | 400 days | the same point |
| A case's audit trail — timestamps and event kinds, no content | 400 days | the same point |
| The mandate and verdicts behind a sanction | 400 days | the moment the last mark they justify expires or is cleared |

Two of those deserve their reasons stated.

**Images go first, and by a lot.** A photograph is the most intrusive
thing anyone discloses here, and once a case and its appeal are over
there is nothing left that needs it. The record of what the picture was
— its digest, its dimensions, and what was decided — survives without
the picture.

**The sanction record outlives everything, and is never dropped while a
mark is live.** It is also required to outlive the case record and the
audit trail, and this authority refuses to start on a schedule that says
otherwise: the mandate kept with a sanction is what the periods above are
resolved from, so a shorter sanction tail would delete the terms under
which the rest of the record was still due to go, and the record would
then be kept indefinitely against the period on this page.

A device's marks are two bits with no explanation
attached. The verdict is the only thing that says what they mean and the
only basis on which one can be lifted. Deleting it while a mark is in
force would leave someone marked with no way to show why or to have it
cleared, so a permanent ban means the record stays permanently. That is
not an exception to this schedule; it is what the schedule is for.

One of those is not pinned by your consent, and it is the only one: an
upload no report ever named belongs to no case, so there is no mandate
whose terms could govern it. It is a bound on how long this service
holds unclaimed bytes. Every other period above is read from the
manifest the case's accused agreed to, so republishing a shorter one
does not reach back into cases already open.

## What is not on a timer

The `cases` row itself — that a case existed, its class, and how it
ended — is kept. It holds no disclosed content, and it is what makes the
counts in the transparency report answerable.

## Preservation overrides all of it

Where law specifically requires this authority to preserve material, a
**preservation hold** is placed on it, and a hold outranks every period
above. Nothing in this service deletes held material: not the sweep, not
a case ending, not a class refusing media afterwards.

A hold's release date is fixed when the hold is placed, from the period
published at that moment. A later version of this document naming a
shorter period does not shorten a hold already running — the same way a
mandate is judged by the terms it pinned rather than by today's.

A hold is not released by its date alone. If no referral has been
recorded against it, the material stays and the case stays in the
operator's queue: the period bounds how long material must be kept
*after* it has been referred, and it is not permission to discard
evidence nobody ever passed on. That can mean material is held longer
than this schedule wants, which is the direction to err in.

Holds only exist for classes this manifest declares preservation terms
for. **This manifest declares none.** No class here accepts media
evidence that would need preserving, and the classes that would require
it refuse it — see [lawful reporting](./lawful-reporting.md) for what
that means and why.

## What deletion is, and is not

Deleting media deletes the original and every derived copy together. A
deletion that left a viewable version behind would not be one.

This service runs its sweep on an interval and compares wall-clock
times, so a period is honoured even across a restart or an outage that
spans it. It logs what it deleted. What it cannot promise is anything
about copies outside its own storage: backups, if an operator keeps
them, are the operator's to account for, and this document speaks only
for what this service holds.
