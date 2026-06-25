# HOMESERVER vault payload

Payload authority for HOMESERVER files installed under `/vault/scripts`.

The deployable side packs this repository. The target side unpacks it by moving/copying the payload into `/vault/scripts` after Keyman and sudoers are standing. This repository does not carry vault secrets and does not own the encrypted partition policy itself.

## Placement in the HOMESERVER ladder

1. Keyman stands first and creates/preserves the key hierarchy.
2. sudoers stands next so privileged actuator policy is declared.
3. Vault payload lands by copying this repository into `/vault/scripts`.
4. Main `sbin` entries land on the system path.
5. Systemd units, UDEV rules, network link files, and linker/user-local-lib follow as separate boundaries.

## Encryption boundary found in the quarry

The legacy bootstrap has two vault paths:

- modern mode: `/vault` is expected to be preseed-configured and mounted or mountable by `homeserver-vault` partlabel;
- legacy mode: `cryptsetup luksFormat /dev/disk/by-partlabel/homeserver-vault --key-file /root/key/skeleton.key`, open as `homeserver-vault_crypt`, `mkfs.ext4`, then mount `/vault`.

The later finale/dev cleanup route rotated a LUKS vault from `HOMESERVER_DEPLOY_EPHEMERAL_KEY_2024` to `/root/key/skeleton.key`. That confirms vault encryption belongs in the vault Chrysalis module, with redacted receipts and Keyman skeleton authority, not inside this payload repo.

See `manifest.json` for the exact contract and ordered consumers.
