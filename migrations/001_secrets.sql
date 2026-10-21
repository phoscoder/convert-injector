-- co-injector: schema, tables and roles.
-- Run once per database, as a superuser (or a role with CREATEROLE that can SET ROLE):
--   psql "$ADMIN_DATABASE_URL" -f migrations/001_secrets.sql

BEGIN;

-- Roles: one owner nobody logs in as, one read-only role for `run`,
-- one read-write role for `set` / `unset` / `list`. Passwords are set afterwards with \password.
CREATE ROLE secrets_owner NOLOGIN;
CREATE ROLE secrets_reader LOGIN;
CREATE ROLE secrets_writer LOGIN;
GRANT secrets_owner TO CURRENT_USER;  -- lets this script create objects as the owner

CREATE SCHEMA secrets AUTHORIZATION secrets_owner;
SET LOCAL ROLE secrets_owner;         -- everything below is owned by secrets_owner

CREATE TABLE secrets.systems (
  id     SERIAL PRIMARY KEY,
  name   TEXT UNIQUE NOT NULL,        -- backend, worker, frontend
  domain TEXT,
  type   TEXT NOT NULL                -- api, worker, web
);

CREATE TABLE secrets.environments (
  id   SERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL           -- development, staging, production
);

CREATE TABLE secrets.secrets (
  id             SERIAL PRIMARY KEY,
  system_id      INT REFERENCES secrets.systems(id) ON DELETE CASCADE,  -- NULL = shared by all systems
  environment_id INT NOT NULL REFERENCES secrets.environments(id) ON DELETE CASCADE,
  key            TEXT NOT NULL CHECK (key ~ '^[A-Z_][A-Z0-9_]*$'),
  value          BYTEA NOT NULL,      -- encrypted: 24-byte nonce || ciphertext + tag
  description    TEXT,
  is_public      BOOLEAN NOT NULL DEFAULT false,                       -- safe for the frontend bundle
  updated_by     TEXT NOT NULL,
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One value per key per scope. Two partial indexes instead of NULLS NOT DISTINCT,
-- so this works on any supported Postgres version.
CREATE UNIQUE INDEX secrets_unique_system ON secrets.secrets (system_id, environment_id, key)
  WHERE system_id IS NOT NULL;
CREATE UNIQUE INDEX secrets_unique_shared ON secrets.secrets (environment_id, key)
  WHERE system_id IS NULL;

-- Access. Your app's own database user gets nothing here.
GRANT USAGE ON SCHEMA secrets TO secrets_reader, secrets_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA secrets TO secrets_reader;
GRANT SELECT ON secrets.systems, secrets.environments TO secrets_writer;
GRANT SELECT, INSERT, UPDATE, DELETE ON secrets.secrets TO secrets_writer;
GRANT USAGE ON SEQUENCE secrets.secrets_id_seq TO secrets_writer;

-- Your systems and the environment(s) this database serves. Edit to match yours.
INSERT INTO secrets.systems (name, domain, type) VALUES
  ('backend',  'api.example.com', 'api'),
  ('worker',   NULL,              'worker'),
  ('frontend', 'example.com',     'web');

INSERT INTO secrets.environments (name) VALUES ('production');

COMMIT;