# Published policy documents

Every URL in [`../manifest/manifest.json`](../manifest/manifest.json)
points at one of these. They are the terms a user reads before
consenting, so they are sources, not notes about sources: what is
written here is what gets served at `authority.onym.app/policy/...`.

**These are drafts and need sign-off before publication.** They are
written from two things only — the [reference
policy](../../REFERENCE-AUTHORITY-POLICY.md) and what
`authority/src/` actually does — so nothing here should be a surprise
or a promise the code cannot keep. But they commit Onym to specific
undertakings, and that is not a decision code inspection can make.

Two in particular deserve a careful read:

- **`confidentiality.md`** names no deletion schedule, on purpose. §7 of
  the reference policy argues that a period nobody keeps is worse than
  naming none, and this service deletes nothing on a timer. If Onym
  wants to commit to a retention period, the deletion has to be built
  first and the document changed second.
- **`classes.md`** is what the manifest's `definition` URLs resolve to,
  and it is the text an accused person is judged against. It restates
  the reference policy's canonical rules verbatim rather than
  paraphrasing them, because `src/policy.rs` hands a model those exact
  words — a definition here that drifted from that text would mean the
  class someone consented to and the rule the model applied are two
  different things.

Routing: these need to be served under `authority.onym.app/policy/`.
The authority service itself serves only `/manifest.json` and `/v1/*`,
so that is a Caddy concern rather than an application one.
