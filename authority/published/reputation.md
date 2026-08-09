# Reporter reputation

A reporter's track record with this authority affects the **priority**
their report gets at intake. It does not affect whether a case is
decided, or how.

## The weight

Held per reporter, as two counters: reports that ended in a ban, and
reports that ended in a dismissal.

```
weight = 1 + (upheld / (upheld + dismissed))
```

A reporter with no record has weight 1 — heard, just not prioritised.
A reporter every one of whose reports was upheld reaches 2. Nobody
reaches zero: a poor record deprioritises, it does not silence.

## What moves it

Only a decision on the merits, and it moves for **every** reporter
attached to a case rather than whoever filed first — a case three
people reported was upheld or dismissed for all three.

Two things deliberately do not move it:

- **A dismissal at the decision deadline.** That is this authority
  failing to decide in time, not the reporter being wrong. Counting it
  against them would let a stalling authority quietly demote reporters
  it would rather not hear from.
- **A reversal on appeal.** That corrects this authority's own error.
  Nobody's record moves for it.

## No bounty

There is no payment for reporting, and there will not be one. Paid
reporting industrialises false accusation, which is a worse failure
than the one it would be trying to fix.
