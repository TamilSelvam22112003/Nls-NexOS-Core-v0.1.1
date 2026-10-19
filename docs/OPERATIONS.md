# Router-CA operations

## Local commands

```sh
sudo systemctl start nls-ca-status.service
sudo journalctl -u nls-ca-status.service -b --no-pager
sudo -u nls-ca /usr/local/libexec/nls-ca-admin status
```

The status unit is a one-shot local state check. It is not a network service and does not expose enrollment, lookup, policy, or revocation APIs.

## Security and backups

- Keep `/etc/nls-ca/ca.env` root-owned, mode 0640, group `nls-ca`; it contains the secret used to unlock local CA state.
- Keep `/var/lib/nls-ca` mode 0700 and owned by `nls-ca`.
- Back up the encrypted CA state and the passphrase separately, with access controls and restore testing.
- Never run `init` against an existing CA state directory. Do not remove CA state during routine uninstall or upgrades.
- Enrollment credentials are short-lived and displayed once; transfer them securely and avoid logs and shell history.

## Enrollment readiness

After initialization, enrollment is intentionally not ready until enrollment credentials, policy, and access controls have been configured. Run `status` and resolve every reported prerequisite. The CLI currently does not provide a long-running CA server, so a healthy local status does not mean a router can connect to a CA endpoint.

## Upgrade, rollback, and incident response

Preserve `/etc/nls-ca` and `/var/lib/nls-ca` when upgrading. Test the new CLI against a copy of state before replacing a production binary. In a suspected key compromise, restrict filesystem access and use an independently designed recovery/rotation procedure; deleting state is not a safe substitute for revocation.
