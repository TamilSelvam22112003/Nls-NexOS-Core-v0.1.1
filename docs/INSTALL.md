# Router-CA installation (Ubuntu 22.04)

## Scope and limitation

This installs the static `nls-core` Router-CA administration CLI and one-shot systemd units for local initialization and status checks. **It does not install a long-running network CA service**: the current `cmd/nls-core` supports `init`, `set-enrollment-credentials`, `set-policy`, `set-access-controls`, and `status`, but has no network listener. Do not configure routers to depend on this installation as if it were a running enrollment/control endpoint.

Supported architectures: `amd64` and `arm64`. Build requires Go 1.22+, make, and OpenSSL.

## Build static binary

```sh
make clean
make build GOOS=linux GOARCH=amd64
file bin/nls-core
ldd bin/nls-core
```

`make build` uses `CGO_ENABLED=0`, `-trimpath`, and builds the single CLI package. On the target architecture, `ldd` should report that the binary is not a dynamic executable.

## Install

```sh
sudo apt-get update
sudo apt-get install -y golang-go make openssl
sudo ./scripts/install-ca.sh install
sudo systemctl start nls-ca-init.service
sudo systemctl start nls-ca-status.service
```

The installer creates the `nls-ca` system account, a mode-0700 state directory, static CLI, wrappers, units, and an initial random passphrase at `/etc/nls-ca/ca.env`. Securely back up that passphrase. The config is root-owned and group-readable by the CA account so the CLI can decrypt its local state.

Initialization is explicit and must only be run once on a fresh state directory. Do not delete or reinitialize a live CA state directory.

## Configure CA state

Use the installed wrapper so the passphrase is loaded from the protected environment file. Commands run as the `nls-ca` account and write only to `/var/lib/nls-ca`.

```sh
sudo -u nls-ca /usr/local/libexec/nls-ca-admin set-enrollment-credentials --name router-01 --ttl 10m
sudo -u nls-ca /usr/local/libexec/nls-ca-admin set-policy --protect-prefix 2001:db8:100::/48
sudo -u nls-ca /usr/local/libexec/nls-ca-admin set-access-controls --allow-enrollment=true --max-active-routers 1000
sudo systemctl start nls-ca-status.service
```

The enrollment token is displayed once by the CLI. Transfer it to the intended router operator using a secure channel. Do not put it in shell history, command-line arguments, tickets, or logs.

## Uninstall

```sh
sudo ./scripts/install-ca.sh uninstall
```

Uninstall removes the CLI, wrappers, and units but preserves configuration and CA state. To destroy them too, explicitly run `sudo PURGE_NLS_CA=1 ./scripts/install-ca.sh uninstall`. This deletes CA key material and is irreversible; back up and verify the backup before purging.
