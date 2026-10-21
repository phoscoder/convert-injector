# Security TODO

Known weaknesses in co-injector, from a design review. The code has been tested for correct behaviour, but it has **not** been independently audited.

What holds up: XChaCha20-Poly1305 with a random nonce per value, BLAKE3 key derivation, audited crates, ciphertext bound to `env/KEY`, and a loud failure on misconfiguration. A leaked database dump or backup yields only ciphertext.

## Weaknesses

1. **One key shared by every host in an environment.** A compromised worker can read the backend's secrets, because every host holds the same `SECRETS_KEY` and the same `secrets_reader` role.
   *Fix:* one key and one Postgres role per system, plus row-level security on `system_id`.

2. **Encryption doesn't bind the system.** The authenticated data is `env/KEY`, not `system_id`. Someone with write access to the table can copy one system's ciphertext into another system's row with the same key name, and it decrypts.
   *Fix:* include the scope (`system_id` or `shared`) in the authenticated data. This changes the stored format, so it needs a migration or re-encrypt step.

3. **Old values can be replayed or deleted.** There is no versioning. A database writer can roll a secret back to an older ciphertext or delete one.
   *Fix:* a `secrets.secret_versions` table filled by a trigger, and a version counter in the authenticated data.

4. **The cache never expires.** An attacker who can block Postgres can force a start on stale values, such as a key that has since been rotated.
   *Fix:* a `--max-cache-age` that refuses an older cache.

5. **TLS isn't enforced.** Without `sslmode=verify-full` in `SECRETS_DB_URL`, a network attacker can't read secrets but can block or downgrade the connection, which also triggers the cache fallback.
   *Fix:* warn or refuse on a remote host when TLS isn't verified.

6. **Secrets are readable on the host.** Env vars can be read by the same user or root, inherited by child processes, and dumped in crash reports. `SECRETS_KEY` sits on every host, so whoever owns a host owns that environment's secrets.
   *Fix:* fetch the key from a cloud KMS or secrets manager at boot instead of an env file.

## Smaller gaps

- The key isn't wiped from memory after use.
- No key rotation command. `set` refuses a new key once values exist.
- Only the last writer is recorded. *Fix:* `pgaudit` on the `secrets` schema.

## Suggested order

1. #5 TLS warning, #4 cache max age (cheap, no format change)
2. #2 bind `system_id` (format change, do early while there are no real deployments)
3. #1 per-system keys and roles, #3 versioning, key rotation
4. #6 KMS-backed key
