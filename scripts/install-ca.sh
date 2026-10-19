#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ACTION="${1:-install}"
PREFIX=/usr/local
CONFIG_DIR=/etc/nls-ca
STATE_DIR=/var/lib/nls-ca
UNIT_DIR=/etc/systemd/system
ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"

case "$ACTION" in install|uninstall) ;; *) echo "usage: $0 [install|uninstall]" >&2; exit 2;; esac
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

if [[ "$ACTION" == uninstall ]]; then
  systemctl stop nls-ca-init.service nls-ca-status.service 2>/dev/null || true
  rm -f "$UNIT_DIR/nls-ca-init.service" "$UNIT_DIR/nls-ca-status.service" \
    "$PREFIX/libexec/nls-ca-admin" "$PREFIX/libexec/nls-ca-init" \
    "$PREFIX/libexec/nls-ca-status" "$PREFIX/sbin/nls-core"
  systemctl daemon-reload
  systemctl reset-failed nls-ca-init.service nls-ca-status.service 2>/dev/null || true
  echo "Uninstalled NLS CA CLI and units. Config/state retained at $CONFIG_DIR and $STATE_DIR."
  if [[ "${PURGE_NLS_CA:-0}" == 1 ]]; then
    rm -rf "$CONFIG_DIR" "$STATE_DIR"
    echo "PURGE_NLS_CA=1: removed CA config and state, including private CA material."
  fi
  exit 0
fi

case "$ARCH" in amd64) GOARCH=amd64;; arm64) GOARCH=arm64;; *) echo "unsupported architecture: $ARCH (supported: amd64, arm64)" >&2; exit 1;; esac
command -v go >/dev/null 2>&1 || { echo "Go is required to build; install Go 1.22+" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "openssl is required to create a random initial passphrase" >&2; exit 1; }
make -C "$ROOT_DIR" build GOOS=linux GOARCH="$GOARCH"
install -d -o root -g root -m 0755 "$PREFIX/sbin" "$PREFIX/libexec" "$CONFIG_DIR" "$UNIT_DIR"
if ! id nls-ca >/dev/null 2>&1; then
  useradd --system --home-dir "$STATE_DIR" --no-create-home --shell /usr/sbin/nologin nls-ca
fi
install -d -o nls-ca -g nls-ca -m 0700 "$STATE_DIR"
install -o root -g root -m 0755 "$ROOT_DIR/bin/nls-core" "$PREFIX/sbin/nls-core"
install -o root -g nls-ca -m 0750 "$ROOT_DIR/scripts/nls-ca-admin" "$PREFIX/libexec/nls-ca-admin"
install -o root -g nls-ca -m 0750 "$ROOT_DIR/scripts/nls-ca-init" "$PREFIX/libexec/nls-ca-init"
install -o root -g nls-ca -m 0750 "$ROOT_DIR/scripts/nls-ca-status" "$PREFIX/libexec/nls-ca-status"
install -o root -g root -m 0644 "$ROOT_DIR/systemd/nls-ca-init.service" "$UNIT_DIR/nls-ca-init.service"
install -o root -g root -m 0644 "$ROOT_DIR/systemd/nls-ca-status.service" "$UNIT_DIR/nls-ca-status.service"
if [[ ! -e "$CONFIG_DIR/ca.env" ]]; then
  passphrase="$(openssl rand -hex 32)"
  umask 077
  printf 'NLS_CA_PASSPHRASE=%s\nCA_STATE_DIR=%s\n' "$passphrase" "$STATE_DIR" > "$CONFIG_DIR/ca.env"
  chown root:nls-ca "$CONFIG_DIR/ca.env"
  chmod 0640 "$CONFIG_DIR/ca.env"
  echo "Generated an initial random CA-state passphrase in $CONFIG_DIR/ca.env; back it up securely."
else
  chown root:nls-ca "$CONFIG_DIR/ca.env"
  chmod 0640 "$CONFIG_DIR/ca.env"
fi
systemctl daemon-reload
echo "Installed static Router-CA CLI and one-shot initialization/status units."
echo "Initialize explicitly with: systemctl start nls-ca-init.service"
echo "Then configure enrollment credentials, policy and access controls; see docs/INSTALL.md."
echo "IMPORTANT: this repository currently has no long-running CA network server. These units do not listen on a network port."
