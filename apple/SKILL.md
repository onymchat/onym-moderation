---
name: deploy-onym-moderation-apple
description: Deploy the Onym moderation enforcement backend (Apple DeviceCheck profile) to a DigitalOcean droplet. Use when asked to deploy, redeploy, or stand up the moderation backend, or to check/repair an existing deployment. Requires a DigitalOcean API key.
---

# Deploying the moderation enforcement backend

This service holds the Apple DeviceCheck private key, which makes it
the only thing in the system that can write a device mark. Deploying it
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
6. **`secrets/devicecheck.p8`** — the `AuthKey_<KEYID>.p8` from the
   Apple developer portal, plus its key id and team id in `.env`.
   Without it the service still starts, but every gate check answers
   `checkRequired` and no user can use the app.

## Deploy

```bash
cd ~/Developer/onym-moderation/apple
./deploy/digitalocean/deploy.sh
```

The script is idempotent: it reuses the droplet recorded in `.env` (or
adopts one named `onym-moderation-apple`), re-syncs sources, and
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

`/health` reports whether DeviceCheck is configured, whether signature
enforcement is on, and the interface's public countersigning key.
Confirm all three are what you expect — `deviceCheck: false` means the
deployment is inert.

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
- **`MODERATION_DEVICECHECK_ENV` does not match the app build under
  test.** A token minted by a debug build is only valid against
  `development`, and vice versa; a mismatch looks exactly like "all
  users are banned".

## Operating notes

- **Back up `/data`.** It holds the verdict record and the write log.
  Apple stores two bits per device and nothing else, so a lost store
  cannot be reconstructed — the bits keep their values with no
  surviving explanation of why (profile §8 gap 2).

  ```bash
  ssh root@$DROPLET_IP 'docker run --rm -v onym-moderation-apple_moderation-data:/d \
      -v /root:/backup alpine tar czf /backup/moderation-data.tgz -C /d .'
  ```

- **Logs**: `ssh root@$DROPLET_IP 'cd /opt/onym-moderation-apple && docker compose logs -f moderation'`
- **Restart**: same directory, `docker compose restart moderation`.
- **Rotating the DeviceCheck key**: replace `secrets/devicecheck.p8`,
  update `MODERATION_DEVICECHECK_KEY_ID`, redeploy. Bits already
  written survive — they belong to the developer account, not the key.

## What this service is not

It is not the moderation authority. It executes verdicts; it does not
decide them. If a task asks you to open a case, dismiss one, or issue a
ban, that belongs to the authority's own service — this one would
rightly refuse, because the only object that moves a mark here is a
verdict signed by the designated authority's key.
