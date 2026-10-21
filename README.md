# secrets-inject

**Encrypted secrets from the Postgres you already run, injected as environment variables.**

`secrets-inject` is a small Rust CLI. Your secrets live encrypted in a `secrets` schema in Postgres; each service starts with `secrets-inject run -- <your command>` and receives them as plain env vars. No `.env` files, no new infrastructure, and if Postgres is down your service still boots from an encrypted cache of the last good fetch.

```console
$ secrets-inject run --system backend --env production -- node dist/server.js
secrets-inject: loaded 12 secrets for backend/production
```

Your application code doesn't change. It keeps reading `process.env` (or `os.environ`, or `std::env`).

## Why

- **Nothing on disk in plaintext.** No `.env` to leak, commit, or leave in a backup.
- **One thing to operate.** Postgres is already there. There is no Vault cluster to run.
- **Survives outages.** A dead database means a warning and a cached start, not a failed deploy.
- **Fails loudly on mistakes.** A wrong key, wrong password or typo in a system name is an error, never silently papered over with stale values.
- **Small enough to audit.** Four source files. The crypto is [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305) and [`blake3`](https://crates.io/crates/blake3); nothing hand-rolled.

## How it works

```mermaid
flowchart LR
    DB[(Postgres)] --> RUN[secrets-inject] --> APP[your app]
    CACHE[(Encrypted cache)] -.-> RUN
```

Postgres is the source of truth. `secrets-inject` decrypts the values, saves them to the encrypted cache, and starts your app with them as env vars. The cache is only read when Postgres is unreachable.

`run`, in order:

1. Connects as the read-only `secrets_reader` role (5 second timeout).
2. Loads every secret for the system and environment. A system-specific value overrides a shared one.
3. Decrypts each value with the environment's `SECRETS_KEY`.
4. Writes an encrypted cache so the next start works even if Postgres is down.
5. Removes `SECRETS_KEY` and `SECRETS_DB_URL` from the environment, adds the secrets, and **replaces itself** with your app (same PID, nothing left running, signals go straight to your app).

Only two values live outside the database on each host: `SECRETS_DB_URL` and `SECRETS_KEY`.

## Install

Requires Rust 1.94+ (sqlx 0.9) and Postgres 12+. Linux or macOS only: `run` uses Unix `exec` (WSL is fine).

```bash
git clone <this repo> && cd secrets-inject
cargo build --release
sudo install target/release/secrets-inject /usr/local/bin/
```

## Quick start

### 1. Create the schema

Run the migration by hand as an admin (a superuser, or a role with `CREATEROLE`; on RDS the master user works), after editing the `INSERT` lines at the bottom to match your systems and the environment this database serves:

```bash
psql "$ADMIN_DATABASE_URL" -f migrations/001_secrets.sql
psql "$ADMIN_DATABASE_URL"
```
```sql
\password secrets_reader
\password secrets_writer
```

This creates three tables and three roles. **Your app's own database user gets no access to any of it.** Check:

```sql
SET ROLE app_user;
SELECT * FROM secrets.secrets;
-- ERROR:  permission denied for schema secrets
```

| Role | Used by | Can |
| --- | --- | --- |
| `secrets_reader` | every service, via `run` | `SELECT` |
| `secrets_writer` | people managing secrets | `SELECT`, `INSERT`, `UPDATE`, `DELETE` on secrets |
| `secrets_owner` | nobody (`NOLOGIN`) | owns the objects |

Run the migration as an admin, **not** through your app's migration tool: that usually runs as the app user, which must never own this schema. Use one database per environment.

### 2. Generate a key per environment

```bash
secrets-inject keygen   # run once each for development, staging, production
# 3f9c...e21a  (64 hex characters)
```

Store each key in a password manager before adding any secrets. **Lose a key and every secret encrypted with it is unrecoverable.** Never commit a key or reuse one across environments.

### 3. Add secrets

```bash
read -rsp "SECRETS_KEY: " SECRETS_KEY && export SECRETS_KEY && echo
read -rsp "SECRETS_DB_URL: " SECRETS_DB_URL && export SECRETS_DB_URL && echo
# paste: postgres://secrets_writer:PASSWORD@your-db-host:5432/app?sslmode=require

# Shared by every system (prompts for the value, hidden as you type)
secrets-inject set DATABASE_URL --shared --env production

# Only for one system
secrets-inject set STRIPE_SECRET_KEY --system backend --env production --description "Stripe live key"

# Override a shared value for one system
secrets-inject set REDIS_URL --system worker --env production

# Public: safe to bake into the frontend bundle
echo "https://example.com" | secrets-inject set NEXT_PUBLIC_APP_URL --system frontend --env production --public

# From a file (multi-line values like PEM keys are kept intact)
secrets-inject set JWT_PRIVATE_KEY --system backend --env production < jwt.pem
```

Values are read from a hidden prompt or stdin, never from an argument, so they stay out of shell history and `ps`. To change a value, run `set` again (pass `--public` again if it should stay public; omitting it makes the secret private).

### 4. Run your app

On each host set `SECRETS_DB_URL` (the **reader** URL) and that environment's `SECRETS_KEY`, then:

```bash
secrets-inject run --system backend --env production -- node dist/server.js
```

## Commands

| Command | Who runs it | What it does |
| --- | --- | --- |
| `keygen` | You, once per environment | Prints a new random 32-byte key (hex) |
| `set KEY --system S \| --shared --env E` | Whoever manages secrets | Reads a value from stdin or a hidden prompt, encrypts, saves |
| `unset KEY --system S \| --shared --env E` | Whoever manages secrets | Deletes one secret |
| `list --env E [--system S]` | Whoever manages secrets | Shows keys, scope, who changed them, when; **never values** |
| `run --system S --env E [--public-only] [--no-cache] [--cache-dir D] -- CMD...` | Every service, at startup | Fetches, decrypts, caches, then `exec`s your command |

```console
$ secrets-inject list --env production
KEY                  SCOPE       PUBLIC  UPDATED           BY
DATABASE_URL         shared              2026-10-19 11:09  victor
NEXT_PUBLIC_APP_URL  frontend    yes     2026-10-19 11:09  victor
REDIS_URL            shared              2026-10-19 11:09  victor
REDIS_URL            worker              2026-10-19 11:09  victor
STRIPE_SECRET_KEY    backend             2026-10-19 11:09  victor
```

With `--system`, `list` shows exactly what that system receives, including the shared values it inherits.

Environment variables: `SECRETS_DB_URL`, `SECRETS_KEY` (required), `SECRETS_CACHE_DIR` (default `~/.cache/secrets-inject`), `SECRETS_USER` (recorded as `updated_by`, defaults to `$USER`).

Names must be `UPPER_SNAKE_CASE`, enforced by the CLI and by a `CHECK` constraint on the table.

### When does it fall back to the cache?

A misconfiguration must never hide behind stale values, so **only genuine outages use the cache**.

| Situation | What `run` does |
| --- | --- |
| Postgres down, refusing connections, or timing out | Uses the cache, prints a warning with its age |
| Wrong password, missing permission, missing database or table | Fails immediately |
| Unknown system or environment name | Fails immediately |
| `SECRETS_KEY` can't decrypt a value | Fails immediately |
| No cache yet, or the cache was tampered with | Fails immediately |

## Security model

- **XChaCha20-Poly1305**, fresh random 24-byte nonce per value. Stored as `nonce || ciphertext+tag`.
- **Values are bound to their location.** Each is encrypted with `"<environment>/<KEY>"` as authenticated data, so someone with write access to the table can't copy the production Stripe key into another variable's row or another environment: decryption fails. (Tested.)
- **Separate keys per purpose.** The cache uses a key derived from `SECRETS_KEY` with BLAKE3, so one key never serves two purposes. The cache is also bound to its system and environment.
- **Least privilege.** `run` uses a read-only role. `list` never selects the value column at all.
- **`set` refuses to mix keys.** If your `SECRETS_KEY` can't decrypt a value already stored in that environment, nothing is written.
- **The app never sees the bootstrap values.** `SECRETS_KEY` and `SECRETS_DB_URL` are removed before `exec`.
- **Cache files** are `0600` in a `0700` directory, written to a temp file and renamed so a crash never leaves a broken cache. `--public-only` fetches use a separate `.public` cache, so a frontend cache can never contain backend secrets.

The cache protects against stray copies (backups, disk snapshots, someone browsing files). It does **not** protect against an attacker with full control of the host, since `SECRETS_KEY` is on the same machine; but such an attacker can already read the secrets from your running app's memory.

### Security checklist

- [ ] Each environment has its own `SECRETS_KEY`, stored in a password manager
- [ ] Your app's database user gets `permission denied` on the `secrets` schema
- [ ] `secrets_writer` credentials exist only on the machines of people who manage secrets
- [ ] `SECRETS_DB_URL` uses `?sslmode=require` (or `verify-full`) whenever Postgres is on another host
- [ ] `SECRETS_KEY` is never in a Dockerfile `ENV`, an image, or a committed file
- [ ] Old `.env` files are deleted, and `.env*` is in `.gitignore`
- [ ] Every secret that was ever committed to git has been rotated
- [ ] Each service has its own cache volume or cache directory

> Point `SECRETS_DB_URL` straight at Postgres, not through PgBouncer in transaction mode: sqlx uses prepared statements, which older PgBouncer setups break.

## Deploying

Every service starts the same way: `secrets-inject run --system <name> --env <env> -- <your usual start command>`.

### Importing an existing `.env`

Skips comments and empty values, strips `export` and surrounding quotes, keeps values containing `=` intact. Run once per system; move variables everyone uses to `--shared` afterwards and `unset` the per-system copies. Delete the `.env` once `run` works.

```bash
grep -E '^(export )?[A-Z_][A-Z0-9_]*=.+' .env.production | sed 's/^export //' | while IFS= read -r line; do
  k="${line%%=*}"; v="${line#*=}"
  v="${v#\"}"; v="${v%\"}"; v="${v#\'}"; v="${v%\'}"
  printf '%s' "$v" | secrets-inject set "$k" --system backend --env production
done
```

### Docker

Build the binary in a separate stage. The Rust stage must use the same C library as your app image (Debian-based `node:22-bookworm-slim` pairs with `rust:1-bookworm`; for Alpine use `rust:1-alpine`).

```dockerfile
FROM rust:1-bookworm AS secrets-inject
WORKDIR /src
COPY secrets-inject/ .
RUN cargo build --release

FROM node:22-bookworm-slim
COPY --from=secrets-inject /src/target/release/secrets-inject /usr/local/bin/secrets-inject
WORKDIR /app
# ... your usual COPY / npm ci / npm run build steps ...

ENV SECRETS_CACHE_DIR=/var/cache/secrets-inject
RUN mkdir -p /var/cache/secrets-inject && chown node:node /var/cache/secrets-inject
USER node

CMD ["secrets-inject", "run", "--system", "backend", "--env", "production", "--", "node", "dist/server.js"]
```

In Compose, mount a cache volume per service or the cache is lost whenever a container is recreated:

```yaml
services:
  backend:
    image: myapp
    init: true   # node becomes PID 1 after exec; this forwards signals and reaps zombies
    environment:
      - SECRETS_DB_URL   # passed through from the host, never written here
      - SECRETS_KEY
    volumes:
      - secrets-cache-backend:/var/cache/secrets-inject

  worker:
    image: myapp
    init: true
    command: ["secrets-inject", "run", "--system", "worker", "--env", "production", "--", "node", "dist/worker.js"]
    environment: [SECRETS_DB_URL, SECRETS_KEY]
    volumes:
      - secrets-cache-worker:/var/cache/secrets-inject

volumes:
  secrets-cache-backend:
  secrets-cache-worker:
```

### systemd

```bash
sudo install -d -m 700 /etc/secrets-inject
sudo install -m 600 /dev/null /etc/secrets-inject/production.env
sudo nano /etc/secrets-inject/production.env
# SECRETS_DB_URL=postgres://secrets_reader:PASSWORD@db-host:5432/app?sslmode=require
# SECRETS_KEY=<the production key>
```

```ini
# /etc/systemd/system/backend.service
[Unit]
Description=Backend API
After=network-online.target

[Service]
User=app
EnvironmentFile=/etc/secrets-inject/production.env
CacheDirectory=backend
Environment=SECRETS_CACHE_DIR=/var/cache/backend
ExecStart=/usr/local/bin/secrets-inject run --system backend --env production -- /usr/bin/node /srv/app/dist/server.js
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

systemd reads the env file as root before switching to the app user. For `worker.service`, change the system name, cache directory and command.

### Local development

Each developer puts the **development** reader URL and key in their shell profile once. Developers never receive production keys.

```json
{
  "scripts": {
    "dev": "secrets-inject run --system backend --env development -- tsx watch src/index.ts",
    "dev:worker": "secrets-inject run --system worker --env development -- tsx watch src/worker.ts"
  }
}
```

### Frontend builds

Public values are baked into the JavaScript bundle at build time, so wrap the build with `--public-only`. Only rows marked `--public` are loaded, so a backend secret can't reach browser code even if someone mistypes a name:

```bash
secrets-inject run --system frontend --env production --public-only -- npm run build
```

For Next.js with server-side code that needs private secrets, start the server **without** `--public-only`:

```bash
secrets-inject run --system frontend --env production -- npm start
```

Wherever the build runs (CI included) must be able to reach Postgres.

## Testing

```bash
cargo test                # 21 unit tests: crypto, cache, CLI parsing (no database needed)
scripts/test-e2e.sh       # everything, plus 37 end-to-end tests, on a throwaway Postgres in Docker
PG_VERSION=12 scripts/test-e2e.sh
```

The end-to-end suite drives the real binary against a real Postgres and covers, among other things:

- secrets arrive; `SECRETS_KEY` / `SECRETS_DB_URL` don't
- system-over-shared overrides, per-system scoping, `--public-only` filtering
- the app keeps the **same PID** and its exit code
- cache fallback on refused connections and on a hung server (the 5 s timeout), `--no-cache`
- tampered caches and copied ciphertexts are rejected
- wrong key, wrong password, missing permission and unknown names **fail instead of using the cache**
- the app user is locked out; the reader role can't write; `list` never prints values; values are stored encrypted

To run the e2e tests against your own server, set `SECRETS_TEST_ADMIN_URL` to a **disposable** superuser URL (the suite drops and recreates a `secrets_e2e` database and the migration's roles) and run `cargo test`. Without it the e2e tests skip. CI runs everything on Postgres 12 and 16.

## Project layout

```
secrets-inject/
├── migrations/001_secrets.sql   # schema, tables, roles
├── src/
│   ├── main.rs                  # CLI and commands
│   ├── crypto.rs                # XChaCha20-Poly1305 + key derivation
│   ├── db.rs                    # every Postgres query
│   └── cache.rs                 # encrypted fallback cache
├── tests/e2e.rs                 # end-to-end tests against real Postgres
└── scripts/test-e2e.sh          # Docker-backed test runner
```

## Known limits

| Limit | Fix when you need it |
| --- | --- |
| Every host in an environment shares `secrets_reader`, so a compromised worker can read backend-only secrets | One Postgres role per system, plus row-level security on `system_id` |
| No history of old values | A `secrets.secret_versions` table filled by an `UPDATE`/`DELETE` trigger |
| No key rotation command; `set` refuses a new key once values exist | A `rotate-key` command that re-encrypts every row in one transaction |
| Only the last writer is recorded | Postgres audit logging (`pgaudit`) on the `secrets` schema |

For a small team this is a solid start. Add these as the team or compliance requirements grow.

## License

MIT, see [LICENSE](LICENSE).
