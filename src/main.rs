mod cache;
mod crypto;
mod db;

use std::collections::BTreeMap;
use std::io::{IsTerminal, Read};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use sqlx::PgConnection;

use crate::cache::Cache;
use crate::crypto::SecretKey;

#[derive(Parser)]
#[command(name = "co-injector", version, about = "Encrypted secrets from Postgres, injected as environment variables")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print a new random SECRETS_KEY (one per environment)
    Keygen,
    /// Load secrets and start a command with them as environment variables
    Run(RunArgs),
    /// Encrypt and save a secret (value is read from stdin, or prompted for)
    Set(SetArgs),
    /// Delete a secret
    Unset(UnsetArgs),
    /// List secret names and metadata (never values)
    List(ListArgs),
}

#[derive(Args)]
struct RunArgs {
    #[arg(long)]
    system: String,
    #[arg(long)]
    env: String,
    /// Only load secrets marked public (for frontend builds)
    #[arg(long)]
    public_only: bool,
    /// Where to keep the encrypted fallback cache
    #[arg(long, env = "SECRETS_CACHE_DIR")]
    cache_dir: Option<PathBuf>,
    /// Never read or write the fallback cache
    #[arg(long)]
    no_cache: bool,
    /// The command to start, after `--`
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

/// Exactly one of --system NAME or --shared.
#[derive(Args)]
#[group(required = true, multiple = false)]
struct Scope {
    /// The system this secret belongs to (e.g. backend)
    #[arg(long)]
    system: Option<String>,
    /// Shared by every system in the environment
    #[arg(long)]
    shared: bool,
}

#[derive(Args)]
struct SetArgs {
    /// Variable name, e.g. STRIPE_SECRET_KEY
    key: String,
    #[command(flatten)]
    scope: Scope,
    #[arg(long)]
    env: String,
    /// Safe to expose to the frontend bundle
    #[arg(long)]
    public: bool,
    #[arg(long)]
    description: Option<String>,
    /// Recorded as updated_by (defaults to $USER)
    #[arg(long, env = "SECRETS_USER")]
    by: Option<String>,
}

#[derive(Args)]
struct UnsetArgs {
    key: String,
    #[command(flatten)]
    scope: Scope,
    #[arg(long)]
    env: String,
}

#[derive(Args)]
struct ListArgs {
    #[arg(long)]
    env: String,
    /// Show only what this system would receive
    #[arg(long)]
    system: Option<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let result = match Cli::parse().command {
        Cmd::Keygen => {
            println!("{}", SecretKey::generate().to_hex());
            Ok(())
        }
        Cmd::Run(args) => run(args).await,
        Cmd::Set(args) => set(args).await,
        Cmd::Unset(args) => unset(args).await,
        Cmd::List(args) => list(args).await,
    };
    if let Err(e) = result {
        eprintln!("co-injector: error: {e:#}");
        std::process::exit(1);
    }
}

// ---------- run ----------

enum FetchError {
    /// Postgres is down or unreachable: fall back to the cache.
    Unavailable(anyhow::Error),
    /// Something is misconfigured: fail loudly, never hide it behind the cache.
    Config(anyhow::Error),
}

async fn run(args: RunArgs) -> Result<()> {
    let key = master_key()?;
    let cache = (!args.no_cache).then(|| {
        let dir = args.cache_dir.clone().unwrap_or_else(cache::default_dir);
        Cache::new(&dir, &args.system, &args.env, args.public_only, &key)
    });

    let secrets = match fetch_secrets(&args, &key).await {
        Ok(secrets) => {
            if let Some(cache) = &cache
                && let Err(e) = cache.write(&secrets)
            {
                eprintln!("co-injector: warning: could not write cache: {e:#}");
            }
            eprintln!("co-injector: loaded {} secrets for {}/{}", secrets.len(), args.system, args.env);
            secrets
        }
        Err(FetchError::Config(e)) => return Err(e),
        Err(FetchError::Unavailable(e)) => {
            let Some(cache) = &cache else {
                return Err(e.context("database unavailable and --no-cache is set"));
            };
            eprintln!("co-injector: warning: database unavailable ({e:#}); trying cache");
            let (secrets, age) = cache
                .read()
                .map_err(|cache_err| anyhow!("{e:#}; no usable cache either: {cache_err:#}"))?;
            eprintln!("co-injector: loaded {} secrets from a cache {} old", secrets.len(), human(age));
            secrets
        }
    };

    // Only returns if the command could not be started.
    Err(exec(&args.command, secrets))
}

async fn fetch_secrets(args: &RunArgs, key: &SecretKey) -> Result<BTreeMap<String, String>, FetchError> {
    let url = env_var("SECRETS_DB_URL").map_err(FetchError::Config)?;
    let mut conn = db::connect(&url).await.map_err(classify)?;

    let env_id = db::environment_id(&mut conn, &args.env)
        .await
        .map_err(classify)?
        .ok_or_else(|| FetchError::Config(anyhow!("unknown environment `{}`", args.env)))?;
    let system_id = db::system_id(&mut conn, &args.system)
        .await
        .map_err(classify)?
        .ok_or_else(|| FetchError::Config(anyhow!("unknown system `{}`", args.system)))?;

    let rows = db::fetch(&mut conn, system_id, env_id, args.public_only).await.map_err(classify)?;

    let mut secrets = BTreeMap::new();
    for (name, encrypted) in rows {
        let plain = key
            .decrypt(&encrypted, &aad(&args.env, &name))
            .and_then(|bytes| String::from_utf8(bytes).context("value is not UTF-8"))
            .with_context(|| format!("could not decrypt {name}"))
            .map_err(FetchError::Config)?;
        secrets.insert(name, plain);
    }
    Ok(secrets)
}

/// Wrong password, missing permission, missing database or table = config error.
/// Anything else (connection refused, timeout, server restarting) = unavailable.
fn classify(e: anyhow::Error) -> FetchError {
    let is_config = e.chain().filter_map(|c| c.downcast_ref::<sqlx::Error>()).any(|se| {
        matches!(se, sqlx::Error::Database(d)
            if d.code().is_some_and(|c| c.starts_with("28") || c.starts_with("42") || c.starts_with("3D")))
    });
    if is_config { FetchError::Config(e) } else { FetchError::Unavailable(e) }
}

/// Replace this process with the command. Same PID, signals go straight to the app.
fn exec(command: &[String], secrets: BTreeMap<String, String>) -> anyhow::Error {
    let err = Command::new(&command[0])
        .args(&command[1..])
        .env_remove("SECRETS_KEY") // the app never sees the master key
        .env_remove("SECRETS_DB_URL") // or the reader credentials
        .envs(secrets)
        .exec();
    anyhow::Error::new(err).context(format!("could not start `{}`", command[0]))
}

// ---------- set / unset / list ----------

async fn set(args: SetArgs) -> Result<()> {
    validate_name(&args.key)?;
    let key = master_key()?;
    let value = read_value(&args.key)?;

    let mut conn = db::connect(&env_var("SECRETS_DB_URL")?).await?;
    let env_id = env_id(&mut conn, &args.env).await?;
    let system_id = scope_id(&mut conn, &args.scope).await?;

    // Refuse to mix keys: this key must decrypt what is already stored for the environment.
    if let Some((name, existing)) = db::any_value(&mut conn, env_id).await? {
        key.decrypt(&existing, &aad(&args.env, &name))
            .context("SECRETS_KEY does not match the key already used for this environment")?;
    }

    let by = args.by.or_else(|| std::env::var("USER").ok()).unwrap_or_else(|| "unknown".into());
    db::upsert(
        &mut conn,
        db::NewSecret {
            system_id,
            environment_id: env_id,
            key: &args.key,
            value: key.encrypt(value.as_bytes(), &aad(&args.env, &args.key)),
            description: args.description.as_deref(),
            is_public: args.public,
            updated_by: &by,
        },
    )
    .await?;
    eprintln!("saved {} ({}, {})", args.key, scope_label(&args.scope), args.env);
    Ok(())
}

async fn unset(args: UnsetArgs) -> Result<()> {
    let mut conn = db::connect(&env_var("SECRETS_DB_URL")?).await?;
    let env_id = env_id(&mut conn, &args.env).await?;
    let system_id = scope_id(&mut conn, &args.scope).await?;
    if db::delete(&mut conn, system_id, env_id, &args.key).await? == 0 {
        bail!("{} not found ({}, {})", args.key, scope_label(&args.scope), args.env);
    }
    eprintln!("deleted {} ({}, {})", args.key, scope_label(&args.scope), args.env);
    Ok(())
}

async fn list(args: ListArgs) -> Result<()> {
    let mut conn = db::connect(&env_var("SECRETS_DB_URL")?).await?;
    let env_id = env_id(&mut conn, &args.env).await?;
    let system_id = match &args.system {
        Some(name) => Some(db::system_id(&mut conn, name).await?.ok_or_else(|| anyhow!("unknown system `{name}`"))?),
        None => None,
    };
    let rows = db::list(&mut conn, env_id, system_id).await?;
    let w = rows.iter().map(|r| r.key.len()).max().unwrap_or(3).max(3);
    println!("{:<w$}  SCOPE       PUBLIC  UPDATED           BY", "KEY");
    for r in rows {
        let public = if r.is_public { "yes" } else { "" };
        println!("{:<w$}  {:<10}  {:<6}  {:<16}  {}", r.key, r.scope, public, r.updated_at, r.updated_by);
    }
    Ok(())
}

// ---------- helpers ----------

fn env_var(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is not set"))
}

fn master_key() -> Result<SecretKey> {
    SecretKey::from_hex(&env_var("SECRETS_KEY")?)
}

/// Binds each ciphertext to its environment and name.
fn aad(env: &str, key: &str) -> Vec<u8> {
    format!("{env}/{key}").into_bytes()
}

async fn env_id(conn: &mut PgConnection, name: &str) -> Result<i32> {
    db::environment_id(conn, name).await?.ok_or_else(|| anyhow!("unknown environment `{name}`"))
}

async fn scope_id(conn: &mut PgConnection, scope: &Scope) -> Result<Option<i32>> {
    match &scope.system {
        Some(name) => Ok(Some(db::system_id(conn, name).await?.ok_or_else(|| anyhow!("unknown system `{name}`"))?)),
        None => Ok(None),
    }
}

fn scope_label(scope: &Scope) -> &str {
    scope.system.as_deref().unwrap_or("shared")
}

fn validate_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let ok = chars.next().is_some_and(|c| c.is_ascii_uppercase() || c == '_')
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if !ok {
        bail!("`{name}` is not a valid name: use UPPER_SNAKE_CASE, e.g. STRIPE_SECRET_KEY");
    }
    Ok(())
}

/// Prompt without echo on a terminal; otherwise read stdin (so `cat key.pem | co-injector set ...` works).
fn read_value(name: &str) -> Result<String> {
    let value = if std::io::stdin().is_terminal() {
        rpassword::prompt_password(format!("Value for {name}: "))?
    } else {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        // Drop one trailing newline from `echo`/files; keep newlines inside (PEM keys).
        let trimmed = s.strip_suffix('\n').map(|t| t.strip_suffix('\r').unwrap_or(t)).unwrap_or(&s);
        trimmed.to_string()
    };
    if value.is_empty() {
        bail!("empty value, nothing saved");
    }
    Ok(value)
}

fn human(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs}s"),
        60..3600 => format!("{}m", secs / 60),
        3600..86400 => format!("{}h {}m", secs / 3600, secs % 3600 / 60),
        _ => format!("{}d {}h", secs / 86400, secs % 86400 / 3600),
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        for n in ["A", "_X", "STRIPE_SECRET_KEY", "NEXT_PUBLIC_URL_2"] {
            assert!(validate_name(n).is_ok(), "{n}");
        }
    }

    #[test]
    fn invalid_names() {
        for n in ["", "lower", "Mixed", "1ABC", "A-B", "A B", "A=B", "ÄB"] {
            assert!(validate_name(n).is_err(), "{n}");
        }
    }

    #[test]
    fn aad_binds_env_and_key() {
        assert_eq!(aad("production", "DB"), b"production/DB");
    }

    #[test]
    fn human_durations() {
        assert_eq!(human(0), "0s");
        assert_eq!(human(59), "59s");
        assert_eq!(human(60), "1m");
        assert_eq!(human(3599), "59m");
        assert_eq!(human(3600), "1h 0m");
        assert_eq!(human(3 * 3600 + 120), "3h 2m");
        assert_eq!(human(86400), "1d 0h");
        assert_eq!(human(90000), "1d 1h");
    }

    #[test]
    fn exec_failure_reports_command() {
        let err = exec(&["/nonexistent/definitely-not-here".into()], BTreeMap::new());
        assert!(format!("{err:#}").contains("could not start"));
    }

    #[test]
    fn cli_parses() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
        assert!(Cli::try_parse_from(["x", "set", "K", "--env", "e"]).is_err(), "scope required");
        assert!(Cli::try_parse_from(["x", "set", "K", "--env", "e", "--shared", "--system", "s"]).is_err());
        assert!(Cli::try_parse_from(["x", "set", "K", "--env", "e", "--shared"]).is_ok());
        assert!(Cli::try_parse_from(["x", "run", "--system", "s", "--env", "e"]).is_err(), "command required");
        assert!(Cli::try_parse_from(["x", "run", "--system", "s", "--env", "e", "--", "true"]).is_ok());
    }
}
