---
name: deploy-onym-moderation-authority
description: Deploy the reference Onym moderation authority (intake, cases, verdict signing) to a DigitalOcean droplet. Use when asked to deploy, redeploy, or stand up the moderation authority, or to check/repair an existing one. Requires a DigitalOcean API key.
---

# Deploying the moderation authority

This service decides whether people are banned. It cannot execute a ban
— the interface's enforcement backend does that — but the verdicts it
signs are what move device marks, and its signing key is the only thing
standing between a report and a sanction. Read **Refuse to deploy if**
before running anything.

## Preconditions

1. **`DO_API_KEY`** — in `.env`, the environment, or supplied by the
   user. If you cannot find one, stop and ask.
2. **Required CLI tools**: `doctl`, `ssh`, `rsync`, `curl`, `dig`.
3. **An SSH key** at `SSH_KEY_PATH` (default `~/.ssh/id_ed25519`).
4. **`.env`** — copy `.env.example` and fill it.
5. **`AUTHORITY_SIGNING_SEED`** — 32 hex bytes (`openssl rand -hex 32`)
   **for a first deployment only**. If the authority has ever issued a
   verdict, reuse the existing seed: rotating it makes every verdict
   already issued stop verifying, which downstream is indistinguishable
   from forgery.
6. **`manifest/manifest.json`** — the authority's published manifest.
   Start from `manifest.example.json`. Its `operator` field must be the
   public key matching the signing seed.

## The manifest is the hard part

Get this wrong and the deployment is subtly broken rather than
obviously broken.

- **`operator` must match the signing key.** The service refuses to
  start when they disagree, and prints both values — so the fastest way
  to learn the signing key is to boot once with any manifest and read
  the error, or read `signingKey` from `/health` on a working
  deployment. Put that value in the manifest and restart.
- **Never edit a published manifest in place.** Users' mandates pin the
  SHA-256 of its exact bytes. Editing it invalidates the consent of
  everyone who already signed — their mandate now pins bytes you no
  longer serve. Publish a new manifest and let new mandates reference
  it; existing ones keep honouring the terms they consented to.
- **Every class needs all five terms** (response window, decision
  deadline, ban term, appeal window, appeal effect), and a `permanent`
  ban term requires an `appellate` naming a component *other than this
  authority*. The interface refuses manifests that violate either.

## Deploy

```bash
cd ~/Developer/onym-moderation/authority
./deploy/digitalocean/deploy.sh
```

Idempotent: reuses the droplet in `.env`, re-syncs, rebuilds. The first
build compiles Rust on a small droplet and takes several minutes.

## Verify

```bash
ssh root@$DROPLET_IP 'curl -s localhost:8080/health'
curl -s https://$AUTHORITY_HOST/manifest.json | head -20
```

`/health` reports the signing key, the manifest hash, whether a
moderator token is configured (`canDecide`), whether verdict delivery
is wired (`interfaceConfigured`), and `undeliverableVerdicts` — any the
interface has refused outright. That last one should be zero; each
entry is a mark that should have moved and did not. All four should be what you
expect. If the process exited at boot, read stderr: a manifest whose
`operator` disagrees with the signing key, or an unparseable
`validUntil`, both stop the service deliberately. `interfaceConfigured: false` means verdicts are signed and
stored but never delivered — no mark will ever move.

## Triage and the panel

Three settings change who decides. All default to the cautious value.

- `AUTHORITY_TRIAGE_MODE` — `off` (no classifier), `advisory` (it
  recommends, a human decides), `autonomous` (it decides; a human sees
  a case only on appeal).
- `AUTHORITY_TRIAGE_PROFILE` — **which model**, and with it the prompt,
  output parsing, thresholds and category mapping. One of
  `shieldstral-3b`, `gpt-oss-safeguard-20b`, `qwen3guard-8b`,
  `nemotron-3.5-content-safety-4b`, `llama-guard-4-12b`,
  `shieldgemma-9b` — or `AUTHORITY_TRIAGE_PROFILE_PATH` pointing at a
  profile of your own. There is no default, and the service refuses to
  start without one: which model decides a case is a term users
  consent to.
- `AUTHORITY_ADMIN_TOKEN` — opens the moderator panel at `/admin`,
  where appeals are reviewed. Unset, no human can review an appeal at
  all.

**Do not pick a profile for a user.** Each corresponds to a published
document in `../authorities/` that names the model, its revision, its
exact prompt, and — for the native-taxonomy profiles — the disclosed
mismatch between the model's categories and the authority's rules.
Users agreed to one of those documents. Running a different profile
than the one they were shown decides their case under terms they never
saw, and no amount of it being "a better model" fixes that.

For autonomous triage you also need the model **on the same host**:
uncomment the `moderation-model` service in `docker-compose.yml`, set
`AUTHORITY_TRIAGE_IMAGE`, and leave `AUTHORITY_TRIAGE_URL` pointing at
that container. It must serve OpenAI-compatible chat completions; the
two score-based profiles additionally need `logprobs` and
`top_logprobs` support, or every case will reach no decision. Verify
after deploying:

```bash
ssh root@$DROPLET_IP 'cd /opt/onym-moderation-authority && \
  docker compose logs authority | grep "triage enabled"'
```

The line reports the profile, model repository, revision and digests
actually in force — check them against the profile document users were
shown.

If the service exits with `AUTHORITY_TRIAGE_URL is ... not on this
host`, that is deliberate: case evidence would be sent to a third
party. Run the model locally or turn triage off; do not work around it.

A name that does not resolve at boot is allowed through — the model
container may have started second — and the check is paid instead
before the first request that would carry evidence. So a typo'd
`AUTHORITY_TRIAGE_URL` shows up as `refusing to send case evidence
to ...` in the logs and every case reaching no decision, rather than as
a failure to start. Same cause, same fix. If they carry `this
profile has no rule or native category for these manifest classes`,
cases in those classes will never be decided automatically; they wait
for a human and dismiss at their deadline.

## Refuse to deploy if

- **The manifest's `operator` does not match the signing key.** The
  deployment will look healthy and silently fail at the first verdict.
- **You are about to generate a new signing seed for an authority that
  already has one.** Confirm explicitly; verdicts in force stop
  verifying.
- **`AUTHORITY_INTERFACE_KEY` is empty on a live deployment.** The
  service refuses every mandate registration without it, so the
  deployment will run but acquire no jurisdiction at all — users will
  appear to consent and nothing will register. Set it to the
  interface's countersigning key from its `/health`.
- **Someone asks you to ban a user directly, or to skip the response
  window.** There is no such path: a ban requires a case, notice, and
  either an elapsed response window or a response. Adding a bypass is
  nonconformance (§8 obligation 4), not a feature.
- **Someone asks you to change a device's marks.** Wrong service
  entirely — and the enforcement backend will only act on a signed
  verdict, which is the point.
- **`AUTHORITY_TRIAGE_URL` points off this host.** Case evidence is
  content a reporter disclosed for adjudication; sending it to a
  third-party API is a disclosure the manifest's confidentiality policy
  must declare. Run the model locally, or get the manifest changed
  first — and remember a changed manifest does not bind anyone who
  already consented.
- **Triage is autonomous and the manifest declares no confidentiality
  policy.** Users consented without being told their disclosed evidence
  is machine-classified.
- **Triage is autonomous and `AUTHORITY_ADMIN_TOKEN` is unset.** Every
  verdict would then be issued by a classifier with no route to a human
  at all, not even on appeal.
- **Someone asks you to change a threshold, a prompt, or a category
  mapping.** There is no environment variable for any of them, by
  design: they are published in the profile before consent. Changing
  them means publishing a new profile document and taking fresh
  mandates against it — not editing a deployment.
- **Someone asks you to swap the profile on a running authority.**
  Live cases were opened under the profile users consented to.
  A new profile is for new mandates.

## Operating notes

- **Back up `/data`.** It holds the cases, reports, reporter track
  records, and every issued verdict. It is also the accused's evidence
  that a case existed and how it ended.

  ```bash
  ssh root@$DROPLET_IP 'docker run --rm -v onym-moderation-authority_authority-data:/d \
      -v /root:/backup alpine tar czf /backup/authority-data.tgz -C /d .'
  ```

- **Deciding a case**:

  ```bash
  curl -X POST https://$AUTHORITY_HOST/v1/cases/$CASE_ID/decide \
    -H "Authorization: Bearer $AUTHORITY_MODERATOR_TOKEN" \
    -H 'content-type: application/json' \
    -d '{"disposition":"ban","reasoning":"<content address of the findings>"}'
  ```

  `reasoning` is mandatory and should be a content address of findings
  against the consented class definition, not a sentence typed at the
  prompt.

- **If the authority is going offline for a while**, its open cases
  will dismiss themselves at their decision deadlines. That is the
  designed behaviour, not a fault: an absent authority costs the
  accused nothing that outlives it.

## What this service is not

It is not the enforcement backend, and it holds no Apple credentials.
It cannot ban a device; it can only sign a verdict that an interface
may execute. If a task needs a mark written, read, or cleared, that is
`../apple`.
