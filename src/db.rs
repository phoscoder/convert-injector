//! Everything that talks to Postgres.

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use sqlx::{ConnectOptions, Connection, PgConnection, Row, postgres::PgConnectOptions};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn connect(url: &str) -> Result<PgConnection> {
    let opts: PgConnectOptions = url.parse().context("SECRETS_DB_URL is not a valid Postgres URL")?;
    tokio::time::timeout(CONNECT_TIMEOUT, opts.connect())
        .await
        .map_err(|_| anyhow!("timed out connecting to Postgres after {CONNECT_TIMEOUT:?}"))?
        .context("could not connect to Postgres")
}

/// `Ok(None)` means the database answered but the name doesn't exist.
pub async fn environment_id(conn: &mut PgConnection, name: &str) -> Result<Option<i32>> {
    let row = sqlx::query("SELECT id FROM secrets.environments WHERE name = $1")
        .bind(name)
        .fetch_optional(&mut *conn)
        .await?;
    Ok(row.map(|r| r.get("id")))
}

pub async fn system_id(conn: &mut PgConnection, name: &str) -> Result<Option<i32>> {
    let row = sqlx::query("SELECT id FROM secrets.systems WHERE name = $1")
        .bind(name)
        .fetch_optional(&mut *conn)
        .await?;
    Ok(row.map(|r| r.get("id")))
}

/// Encrypted values for one system in one environment.
/// A system-specific row wins over a shared row (system_id IS NULL) with the same key.
pub async fn fetch(
    conn: &mut PgConnection,
    system_id: i32,
    environment_id: i32,
    public_only: bool,
) -> Result<Vec<(String, Vec<u8>)>> {
    let rows = sqlx::query(
        "SELECT DISTINCT ON (key) key, value
         FROM secrets.secrets
         WHERE environment_id = $1
           AND (system_id = $2 OR system_id IS NULL)
           AND (is_public OR NOT $3)
         ORDER BY key, system_id NULLS LAST",
    )
    .bind(environment_id)
    .bind(system_id)
    .bind(public_only)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows.into_iter().map(|r| (r.get("key"), r.get("value"))).collect())
}

/// Any one existing value in this environment, to check a key before writing with it.
pub async fn any_value(conn: &mut PgConnection, environment_id: i32) -> Result<Option<(String, Vec<u8>)>> {
    let row = sqlx::query("SELECT key, value FROM secrets.secrets WHERE environment_id = $1 LIMIT 1")
        .bind(environment_id)
        .fetch_optional(&mut *conn)
        .await?;
    Ok(row.map(|r| (r.get("key"), r.get("value"))))
}

pub struct NewSecret<'a> {
    pub system_id: Option<i32>,
    pub environment_id: i32,
    pub key: &'a str,
    pub value: Vec<u8>,
    pub description: Option<&'a str>,
    pub is_public: bool,
    pub updated_by: &'a str,
}

/// Insert or update. Works on any Postgres version (no ON CONFLICT on nullable columns needed).
pub async fn upsert(conn: &mut PgConnection, s: NewSecret<'_>) -> Result<()> {
    let mut tx = conn.begin().await?;
    let updated = sqlx::query(
        "UPDATE secrets.secrets
         SET value = $4, description = COALESCE($5, description), is_public = $6,
             updated_by = $7, updated_at = now()
         WHERE system_id IS NOT DISTINCT FROM $1 AND environment_id = $2 AND key = $3",
    )
    .bind(s.system_id)
    .bind(s.environment_id)
    .bind(s.key)
    .bind(&s.value)
    .bind(s.description)
    .bind(s.is_public)
    .bind(s.updated_by)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if updated == 0 {
        sqlx::query(
            "INSERT INTO secrets.secrets
               (system_id, environment_id, key, value, description, is_public, updated_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(s.system_id)
        .bind(s.environment_id)
        .bind(s.key)
        .bind(&s.value)
        .bind(s.description)
        .bind(s.is_public)
        .bind(s.updated_by)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn delete(conn: &mut PgConnection, system_id: Option<i32>, environment_id: i32, key: &str) -> Result<u64> {
    let n = sqlx::query(
        "DELETE FROM secrets.secrets
         WHERE system_id IS NOT DISTINCT FROM $1 AND environment_id = $2 AND key = $3",
    )
    .bind(system_id)
    .bind(environment_id)
    .bind(key)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    Ok(n)
}

pub struct Listed {
    pub key: String,
    pub scope: String,
    pub is_public: bool,
    pub updated_by: String,
    pub updated_at: String,
}

/// Metadata only. Values are never selected.
pub async fn list(conn: &mut PgConnection, environment_id: i32, system_id: Option<i32>) -> Result<Vec<Listed>> {
    let rows = sqlx::query(
        "SELECT s.key, COALESCE(sy.name, 'shared') AS scope, s.is_public, s.updated_by,
                to_char(s.updated_at, 'YYYY-MM-DD HH24:MI') AS updated_at
         FROM secrets.secrets s
         LEFT JOIN secrets.systems sy ON sy.id = s.system_id
         WHERE s.environment_id = $1
           AND ($2::int IS NULL OR s.system_id = $2 OR s.system_id IS NULL)
         ORDER BY s.key, s.system_id NULLS FIRST",
    )
    .bind(environment_id)
    .bind(system_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| Listed {
            key: r.get("key"),
            scope: r.get("scope"),
            is_public: r.get("is_public"),
            updated_by: r.get("updated_by"),
            updated_at: r.get("updated_at"),
        })
        .collect())
}