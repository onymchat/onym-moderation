# The published manifest

`manifest.json` is served verbatim at `/manifest.json` and mounted
read-only into the container. **A mandate pins the SHA-256 of these
exact bytes.** Once one user has consented, editing this file — even
reformatting it — silently invalidates their mandate: the authority can
no longer read the terms their case must be judged under, and refuses
to decide rather than fall forward to whatever is published now.

So there are two eras for this file, and only one edit that crosses
between them.

## Before the first mandate

Editable. Two things must happen before this deployment takes a single
mandate:

1. **Replace `operator`.** It currently holds all zeros, which is a
   placeholder and not a key. It must be `onym:key:<hex>` of the public
   half of `AUTHORITY_SIGNING_SEED`. The service **refuses to start**
   when they disagree — verdicts signed by a key the manifest does not
   name are unverifiable, and a warning would produce an authority that
   looks fine and issues nothing anyone can check. The value is in the
   `authority starting` log line as `signing_key`.

2. **Publish every document it links to.** Every URL here is a term a
   user consents to before they can be reported or judged. A link that
   404s is a term nobody agreed to because nobody could read it. The
   sources live in [`../published/`](../published/); they need a route
   that serves them at `authority.onym.app/policy/...`.

## After the first mandate

Frozen. Changing the terms means publishing a *new* manifest and taking
fresh mandates against it. Existing mandates keep pointing at the old
bytes, which is why the store keeps a snapshot of every manifest it has
ever seen — a live case is judged by the manifest its accused agreed
to, never by the current one.

## Decisions taken here, and why

**No `permanent` ban term, and no `appellate`.** The reference policy
allows a permanent ban for `csam`, but §6 makes one valid *only* while
the manifest's independent appellate authority can hear an appeal, and
§8 repeats it: "an existing ban remains only while a living declared
forum can hear an appeal." No such forum exists yet, and this
authority's own moderator is not one — an authority reviewing appeals
against its own verdicts is the thing an appellate is for.

Declaring `permanent` anyway would publish a sanction the contract
requires the interface to clear, so it would be both a false promise
and a weaker outcome than the finite term it replaced. `csam` therefore
carries `P365D`, the heaviest finite term the reference policy uses.
Publishing *below* a maximum is permitted (§2.2, §8); publishing above
one is not. When an independent appellate exists, a new manifest can
raise it, for mandates taken from that point on.

**No `modelProfile`, so no autonomous triage.** Every case is decided
by a human, and the service refuses to start in autonomous mode without
this field — deliberately, because nothing would then bind the
classifier that decides cases to anything a user agreed to.

This is the conforming order rather than a limitation to route around:
someone who consented to "a person decides" must not be switched to "a
model decides" by an environment variable. Introducing triage means
declaring the profile here, publishing the new manifest, and taking
fresh mandates against it. Boot logs a warning while the field is
absent; that warning is describing this choice, not a misconfiguration.

**Terms otherwise track the reference policy** (§2), whose canonical
rules `src/policy.rs` transcribes and whose digest every published
model profile states. Deviating from them is allowed with disclosure,
but a term that differs from the rule a model is asked to apply is a
gap between what was consented and what was decided.
