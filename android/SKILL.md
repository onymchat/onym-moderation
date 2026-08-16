---
name: deploy-onym-moderation-android
description: Deploy the Onym moderation enforcement backend (Google Play Integrity device-recall profile) to a DigitalOcean droplet. Use when asked to deploy, redeploy, or stand up the moderation backend, or to check/repair an existing deployment. Requires a DigitalOcean API key.
---

# Deploying the moderation enforcement backend

This service holds the Google service-account key of the Cloud project
linked in the Play Console, which makes it the only thing in the system
that can write a device mark. Deploying it
carelessly can ban devices or, worse, quietly stop enforcing. Read the
**Refuse to deploy if** list before running anything.

## Preconditions

Check each. Do not improvise around a missing one.

1. **`DO_API_KEY`** — in `.env`, the environment, or supplied by the
   user. If you cannot find one, stop and ask; do not create
   infrastructure with a key you guessed at.
2. **Required CLI tools**: `doctl`, `ssh`, `rsync`, `curl`, `dig`.
3. **An SSH key** at `SSH_KEY_PATH` (default `~/.ssh/id_ed25519`) with
   its `.pub` alongside.
4. **`.env`** — copy `.env.example` and fill it. Never invent values
   for the two below.
5. **`MODERATION_INTERFACE_SIGNING_SEED`** — 32 hex bytes. Generate
   with `openssl rand -hex 32` **only for a first deployment**. If the
   service has ever run, reuse the existing seed: rotating it
   invalidates every countersignature already issued, so every existing
   mandate stops verifying.
6. **`secrets/play-sa.json`** — the service-account JSON key of the
   Google Cloud project linked in the Play Console, plus
   `MODERATION_PLAY_PACKAGE_NAME` and
   `MODERATION_PLAY_CERT_SHA256_DIGESTS` in `.env`. Without it the
   service still starts, but every gate check answers `checkRequired`
   and no user can use the app.

## Deploy

```bash
cd ~/Developer/onym-moderation/android
./deploy/digitalocean/deploy.sh
```

The script is idempotent: it reuses the droplet recorded in `.env` (or
adopts one named `onym-moderation-android`), re-syncs sources, and
rebuilds. Running it twice is safe and is the normal way to redeploy.

The first build compiles Rust on a 1 GB droplet and takes several
minutes. That is expected — do not kill it and retry, which only starts
the compile over.

## Verify

The script fails loudly if the service does not answer, and prints
recent logs. After it reports success:

```bash
# Local to the droplet (always available):
ssh root@$DROPLET_IP 'curl -s localhost:8080/health'

# Public (only once DNS + ACME have settled):
curl -s https://$MODERATION_HOST/health
```

`/health` reports whether Play Integrity is configured, whether signature
enforcement is on, and the interface's public countersigning key.
Confirm all three are what you expect — `playIntegrity: false` means
the deployment is inert.

Then check the write log's hash chain is intact:

```bash
curl -s https://$MODERATION_HOST/v1/write-log | head -40   # chainIntact: true
```

## DNS

`MODERATION_HOST` must have an A record pointing at the droplet, and on
Cloudflare it must be **DNS-only (grey cloud)**. Proxying breaks ACME —
that is what silently broke certificate renewal on the old onym.chat
box. The script warns and continues if DNS is wrong; Caddy retries
issuance, so fixing the record is enough, no redeploy needed.

## Refuse to deploy if

Stop and raise these with the user rather than proceeding:

- **`MODERATION_ENFORCE_SIGNATURES` is not `true` for a production
  deployment.** With it false, any request that reaches the authority
  endpoint can ban a device, because unverifiable verdict signatures
  are accepted. It defaults to false only so a deployment can exist
  before authorities publish signing keys.
- **`MODERATION_AUTHORITY_TOKEN` is empty.** The verdict endpoint now
  fails closed and refuses everything, so the deployment is inert
  rather than dangerous — but it is still not a working deployment.
  Never "fix" it by setting `MODERATION_ALLOW_UNAUTHENTICATED_AUTHORITY=true`
  on a reachable host; that opens an unauthenticated write into the
  store.
- **`MODERATION_AUDIT_TOKEN` is empty and someone wants the write
  log.** Set the token; do not expose the endpoint another way. It
  names every device binding, verdict reference, and mark transition.
- **You are about to generate a new signing seed for a service that
  already has one.** Confirm explicitly; this breaks existing mandates.
- **The user asks you to change a device's bits directly.** There is no
  such endpoint and adding one would be nonconformance: marks move only
  on signed verdicts (Moderation.md §11.2). Route the request to the
  authority that issues verdicts.
- **`MODERATION_PLAY_CERT_SHA256_DIGESTS` does not match the build
  under test.** A debug-signed build carries a different signing
  certificate than the Play App Signing one; the classifier then
  refuses every token, which looks exactly like "all users are
  banned". A sideloaded build additionally fails `PLAY_RECOGNIZED` /
  `LICENSED` by design.

## Operating notes

- **Back up `/data`.** It holds the verdict record and the write log.
  Google stores three values and coarse write dates per device and
  nothing else, so a lost store cannot be reconstructed — the values
  keep their state with no surviving explanation of why (profile §8
  gap 7).

  ```bash
  ssh root@$DROPLET_IP 'docker run --rm -v onym-moderation-android_moderation-data:/d \
      -v /root:/backup alpine tar czf /backup/moderation-data.tgz -C /d .'
  ```

- **The store survives a redeploy, so schema changes must migrate.**
  `moderation-data` is a named volume; `docker compose up -d --build`
  replaces the container and keeps the database. `CREATE TABLE IF NOT
  EXISTS` is a no-op against a table that already exists, so a column
  added to a definition never reaches a store an earlier build created
  and every read that selects it fails — the service comes back up
  refusing verdicts and erroring gate checks, with marks frozen.

  Adding a column means adding it in **two** places in
  `android/src/store.rs`: the `CREATE TABLE` (for fresh databases) and
  the `add_column` list in `migrate()` (for every existing one). If the
  column is not nullable and no default is honest, backfill it — see
  `backfill_decided_at`, and note that the values it fills decide the
  causal fold, so a placeholder there silently reorders history rather
  than merely looking wrong.

  Take a backup before deploying a build that migrates.

- **Logs**: `ssh root@$DROPLET_IP 'cd /opt/onym-moderation-android && docker compose logs -f moderation'`
- **Restart**: same directory, `docker compose restart moderation`.
- **Rotating the service-account key**: mint a new key for the same
  service account (or a new account with the Play Integrity role),
  replace `secrets/play-sa.json`, redeploy. Values already written
  survive — they belong to the Play developer account, not the key.

## What this service is not

It is not the moderation authority. It executes verdicts; it does not
decide them. If a task asks you to open a case, dismiss one, or issue a
ban, that belongs to the authority's own service — this one would
rightly refuse, because the only object that moves a mark here is a
verdict signed by the designated authority's key.
