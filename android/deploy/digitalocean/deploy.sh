#!/usr/bin/env bash
#
# deploy.sh — Deploy the Apple DeviceCheck enforcement backend to
# DigitalOcean.
#
# Stack: Caddy (auto-HTTPS) + the moderation service. Idempotent:
# reuses the droplet recorded in .env, re-syncs config, rebuilds the
# container. Safe to run repeatedly.
#
# Usage:
#   cp .env.example .env && $EDITOR .env
#   cp /path/to/<cloud-project>-service-account.json secrets/play-sa.json
#   ./deploy/digitalocean/deploy.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"
SECRET_KEY="$REPO_ROOT/secrets/play-sa.json"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}==> $*${NC}"; }
ok()    { echo -e "${GREEN}==> $*${NC}"; }
warn()  { echo -e "${YELLOW}==> $*${NC}"; }
err()   { echo -e "${RED}==> ERROR: $*${NC}" >&2; }

# ─── Load + validate config ───────────────────────────────────────────

[ -f "$ENV_FILE" ] || { err "Missing $ENV_FILE — copy .env.example and fill it in."; exit 1; }
set -a; source "$ENV_FILE"; set +a

: "${DO_API_KEY:?set DO_API_KEY in .env}"
: "${MODERATION_HOST:?set MODERATION_HOST in .env}"
: "${CADDY_EMAIL:?set CADDY_EMAIL in .env}"
: "${MODERATION_INTERFACE_SIGNING_SEED:?set MODERATION_INTERFACE_SIGNING_SEED in .env (openssl rand -hex 32)}"

DO_REGION="${DO_REGION:-ams3}"
DO_DROPLET_SIZE="${DO_DROPLET_SIZE:-s-1vcpu-1gb}"
SSH_KEY_PATH="${SSH_KEY_PATH:-$HOME/.ssh/id_ed25519}"
SSH_KEY_PATH="${SSH_KEY_PATH/#\~/$HOME}"

for c in doctl ssh rsync curl dig; do
    command -v "$c" >/dev/null || { err "missing required command: $c"; exit 1; }
done
[ -f "$SSH_KEY_PATH" ] || { err "SSH key not found at $SSH_KEY_PATH"; exit 1; }

# The service runs without DeviceCheck credentials, but then it can
# never clear anyone — every gate check answers `checkRequired`. That
# is a safe failure, not a useful deployment, so say so loudly.
if [ ! -f "$SECRET_KEY" ]; then
    warn "No secrets/play-sa.json — the gate will refuse every device (checkRequired)."
    warn "Copy the linked Cloud project service-account JSON key there to enable enforcement."
fi
if [ "${MODERATION_ENFORCE_SIGNATURES:-false}" != "true" ]; then
    warn "MODERATION_ENFORCE_SIGNATURES is not true — unverifiable verdict signatures are"
    warn "accepted. Do not run a production deployment this way."
fi
if [ -z "${MODERATION_AUTHORITY_TOKEN:-}" ]; then
    if [ "${MODERATION_ALLOW_UNAUTHENTICATED_AUTHORITY:-false}" = "true" ]; then
        err "MODERATION_ALLOW_UNAUTHENTICATED_AUTHORITY=true with no authority token means"
        err "anyone who reaches this host can ban a device. Refusing to deploy."
        exit 1
    fi
    warn "MODERATION_AUTHORITY_TOKEN is empty — the verdict endpoint will refuse every"
    warn "request, so no authority can act. Set it (openssl rand -hex 32)."
fi
if [ -z "${MODERATION_AUDIT_TOKEN:-}" ]; then
    warn "MODERATION_AUDIT_TOKEN is empty — /v1/write-log will be closed, including to you."
fi

save_env() {
    local tmp; tmp="$(mktemp)"
    grep -vE '^(DROPLET_ID|DROPLET_IP)=' "$ENV_FILE" > "$tmp" || true
    { echo "DROPLET_ID=${DROPLET_ID:-}"; echo "DROPLET_IP=${DROPLET_IP:-}"; } >> "$tmp"
    mv "$tmp" "$ENV_FILE"
}

info "Config: host=$MODERATION_HOST size=$DO_DROPLET_SIZE region=$DO_REGION"

# ─── Authenticate ─────────────────────────────────────────────────────

info "Authenticating with DigitalOcean..."
doctl auth init --access-token "$DO_API_KEY" >/dev/null 2>&1
ok "Authenticated"

info "Ensuring SSH key is registered..."
SSH_FP="$(ssh-keygen -lf "${SSH_KEY_PATH}.pub" -E md5 | awk '{print $2}' | sed 's/MD5://')"
if ! doctl compute ssh-key get "$SSH_FP" &>/dev/null; then
    doctl compute ssh-key import "onym-moderation-$(basename "$SSH_KEY_PATH")" \
        --public-key-file "${SSH_KEY_PATH}.pub" >/dev/null
    ok "SSH key uploaded"
else
    ok "SSH key already present"
fi

# ─── Droplet ──────────────────────────────────────────────────────────

DROPLET_NAME="onym-moderation-android"

if [ -n "${DROPLET_ID:-}" ] && doctl compute droplet get "$DROPLET_ID" &>/dev/null; then
    DROPLET_IP="$(doctl compute droplet get "$DROPLET_ID" --format PublicIPv4 --no-header)"
    ok "Reusing droplet $DROPLET_ID ($DROPLET_IP)"
else
    EXISTING="$(doctl compute droplet list --format ID,Name --no-header | awk -v n="$DROPLET_NAME" '$2==n {print $1}')"
    if [ -n "$EXISTING" ]; then
        DROPLET_ID="$EXISTING"
        DROPLET_IP="$(doctl compute droplet get "$DROPLET_ID" --format PublicIPv4 --no-header)"
        ok "Adopted existing droplet $DROPLET_ID ($DROPLET_IP)"
    else
        info "Creating droplet $DROPLET_NAME..."
        DROPLET_ID="$(doctl compute droplet create "$DROPLET_NAME" \
            --region "$DO_REGION" --size "$DO_DROPLET_SIZE" \
            --image docker-20-04 --ssh-keys "$SSH_FP" \
            --format ID --no-header --wait)"
        DROPLET_IP="$(doctl compute droplet get "$DROPLET_ID" --format PublicIPv4 --no-header)"
        ok "Created droplet $DROPLET_ID ($DROPLET_IP)"
        info "Waiting for SSH..."
        for _ in $(seq 1 60); do
            ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$SSH_KEY_PATH" \
                "root@$DROPLET_IP" true 2>/dev/null && break
            sleep 5
        done
    fi
fi
save_env

# ─── DNS check ────────────────────────────────────────────────────────
#
# Caddy cannot obtain a certificate until $MODERATION_HOST resolves to
# this droplet. Cloudflare records must be DNS-only (grey cloud) —
# proxying breaks ACME, which is what silently broke renewal on the old
# onym.chat box.

RESOLVED="$(dig +short "$MODERATION_HOST" | tail -1)"
if [ "$RESOLVED" != "$DROPLET_IP" ]; then
    warn "$MODERATION_HOST resolves to '${RESOLVED:-nothing}', not $DROPLET_IP."
    warn "Point an A record at the droplet (DNS-only, not proxied), then re-run."
    warn "Continuing — Caddy will retry issuance until DNS is right."
fi

# ─── Sync + bring up ──────────────────────────────────────────────────

SSH_OPTS=(-o StrictHostKeyChecking=no -i "$SSH_KEY_PATH")
REMOTE="root@$DROPLET_IP"
REMOTE_DIR="/opt/onym-moderation-android"

info "Syncing sources..."
ssh "${SSH_OPTS[@]}" "$REMOTE" "mkdir -p $REMOTE_DIR"
rsync -az --delete \
    -e "ssh ${SSH_OPTS[*]}" \
    --exclude '.git' --exclude 'target' --exclude '.env' --exclude 'secrets' \
    "$REPO_ROOT/" "$REMOTE:$REMOTE_DIR/"

# .env and the service-account key are copied separately and never rsync'd with
# --delete semantics, so a mistake here can't wipe the key.
info "Syncing secrets..."
scp "${SSH_OPTS[@]}" "$ENV_FILE" "$REMOTE:$REMOTE_DIR/.env" >/dev/null
ssh "${SSH_OPTS[@]}" "$REMOTE" "mkdir -p $REMOTE_DIR/secrets && chmod 700 $REMOTE_DIR/secrets"
if [ -f "$SECRET_KEY" ]; then
    scp "${SSH_OPTS[@]}" "$SECRET_KEY" "$REMOTE:$REMOTE_DIR/secrets/play-sa.json" >/dev/null
    ssh "${SSH_OPTS[@]}" "$REMOTE" "chmod 600 $REMOTE_DIR/secrets/play-sa.json"
fi
ok "Secrets in place"

info "Building and starting (first build compiles Rust; expect a few minutes)..."
ssh "${SSH_OPTS[@]}" "$REMOTE" \
    "cd $REMOTE_DIR && docker compose up -d --build"

# ─── Verify ───────────────────────────────────────────────────────────

info "Waiting for the service to answer..."
HEALTH=""
for _ in $(seq 1 30); do
    HEALTH="$(ssh "${SSH_OPTS[@]}" "$REMOTE" \
        "curl -fsS --max-time 5 http://localhost:8080/health 2>/dev/null" || true)"
    [ -n "$HEALTH" ] && break
    sleep 5
done

if [ -z "$HEALTH" ]; then
    err "Service did not become healthy. Recent logs:"
    ssh "${SSH_OPTS[@]}" "$REMOTE" "cd $REMOTE_DIR && docker compose logs --tail 60 moderation" >&2
    exit 1
fi

ok "Service healthy: $HEALTH"
echo
echo "  Interface countersigning key is in the health output above —"
echo "  publish it in the interface manifest so clients and authorities"
echo "  can verify countersignatures."
echo
info "Public endpoint (once DNS + ACME settle): https://$MODERATION_HOST/health"
ok "Done"
