#!/usr/bin/env bash
# Run ON the Oracle Ubuntu ARM VM after copying owner_panel/ to the server.
# Usage: bash deploy/oracle_setup.sh
set -euo pipefail

cd "$(dirname "$0")/.."
APP_DIR="$(pwd)"
OWNER_PASS="${CROWNAUTH_OWNER_PASSWORD:-ChangeMeNow_$(openssl rand -hex 6)}"
DATA_DIR="${CROWNAUTH_DATA:-/opt/wc-data}"

echo "==> WhiteCrown control plane — Oracle Always Free setup"
echo "    app:  $APP_DIR"
echo "    data: $DATA_DIR"

# Docker
if ! command -v docker >/dev/null 2>&1; then
  echo "==> Installing Docker"
  curl -fsSL https://get.docker.com | sh
  sudo usermod -aG docker "$USER" || true
fi

sudo mkdir -p "$DATA_DIR"
sudo chown -R "$USER:$USER" "$DATA_DIR" || true

echo "==> Building image"
docker build -f deploy/Dockerfile -t wc-auth:latest .

echo "==> Stopping old container (if any)"
docker rm -f wc-auth 2>/dev/null || true

echo "==> Starting (restart=unless-stopped)"
docker run -d \
  --name wc-auth \
  --restart unless-stopped \
  -p 8787:8787 \
  -e CROWNAUTH_PUBLIC=1 \
  -e CROWNAUTH_OWNER_PASSWORD="$OWNER_PASS" \
  -e CROWNAUTH_DATA=/data \
  -e PORT=8787 \
  -v "$DATA_DIR":/data \
  wc-auth:latest

sleep 2
echo "==> Health"
curl -sS "http://127.0.0.1:8787/v2/health" || true
echo
echo "==> DONE"
echo "    Public API:  http://YOUR_PUBLIC_IP:8787/v2/health"
echo "    Panel:       http://YOUR_PUBLIC_IP:8787/c-…… (check logs for path)"
echo "    Owner password (save offline): $OWNER_PASS"
echo
echo "    Firewall: open TCP 8787 (or 80/443) in Oracle Security List + OS ufw if used"
echo "    Optional HTTPS: install Caddy reverse_proxy to 127.0.0.1:8787"
docker logs --tail 30 wc-auth || true
