# Publishing the policy documents

Notes about [`published/`](./published/) — deliberately *not* inside
it. That directory is a serving root: Caddy maps it onto
`authority.onym.app/policy/`, so every file in it is a public URL
whether or not the manifest links to it. This file lived there for one
commit, which meant `/policy/README` served a page announcing that the
terms were unapproved drafts, on the host where people go to read the
terms before consenting.

The rule that follows: **`published/` contains exactly the documents
the manifest points at, and nothing else.** A test enforces it, because
the failure is silent — the directory listing looks fine and the extra
page is only found by someone who guesses the URL.

Every URL in [`manifest/manifest.json`](./manifest/manifest.json)
resolves to one of those files. They are the terms a user reads before
consenting, so they are sources, not notes about sources: what is
written there is what gets served.

**These are drafts and need sign-off before publication.** They are
written from two things only — the [reference
policy](../REFERENCE-AUTHORITY-POLICY.md) and what
`src/` actually does — so nothing here should be a surprise
or a promise the code cannot keep. But they commit Onym to specific
undertakings, and that is not a decision code inspection can make.

Two in particular deserve a careful read:

- **`published/retention.md`** and the `retention` block in
  `manifest/manifest.json` are a live commitment. §7 of the reference
  policy argues that a period nobody keeps is worse than naming none, so
  these were built before they were published — the sweep in
  `deadlines::retention_sweep` enforces every period named, and the
  per-case tails are read from the manifest each case's accused
  consented to rather than from whatever is published today. Changing a
  period is therefore a new manifest and fresh consent, not an edit.

  What this file used to say — that no schedule is named and none is
  kept — was true until media retention shipped and stayed on the page
  afterwards. Read the schedule against the sweep before changing
  either.
- **`published/lawful-reporting.md`** states what happens to preserved
  material: nobody here views it, no model is shown it, the case is not
  decided on it, and it is referred by an operator rather than
  submitted by this service. Each of those is a property of the code,
  not an aspiration; check them before editing the sentence.
- **The three class documents** — `published/csam.md`,
  `credible-violence.md`, `unsolicited-pornography.md` — are what the
  manifest's `definition` URLs resolve to, and they are the text an
  accused person is judged against. Each restates the reference
  policy's canonical rule verbatim rather than paraphrasing it, because
  `src/policy.rs` hands a model those exact words: a definition that
  drifted from that text would mean the class someone consented to and
  the rule that was applied are two different things.

  One document per class, rather than one document with three anchors.
  The manifest's URLs are what a consent screen links to, and a
  fragment cannot address a position in Markdown — a reader following
  the `csam` link would have landed at the top of a four-class page.
  A test pins the correspondence, so a class cannot end up pointing at
  another class's terms.

Routing: these need to be served under `authority.onym.app/policy/`.
The authority service itself serves only `/manifest.json` and `/v1/*`,
so that is a Caddy concern rather than an application one.
