//! End-to-end tests: the real binary against a real Postgres.
//!
//! Needs a superuser connection string in `SECRETS_TEST_ADMIN_URL`; without it every test
//! is skipped. `scripts/test-e2e.sh` starts a throwaway Postgres in Docker and sets it.
//!
//! The suite creates (and first drops) a database called `secrets_e2e` plus the roles
//! from the migration, so point it only at a disposable server.

use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use sqlx::postgres::PgConnectOptions;
use sqlx::{AssertSqlSafe, ConnectOptions, Connection, PgConnection, Row};

const BIN: &str = env!("CARGO_BIN_EXE_secrets-inject");
const DB: &str = "secrets_e2e";

struct Fixture {
    host: String,
    port: u16,
    admin_url: String,
}

impl Fixture {
    fn url(&self, user: &str, pass: &str) -> String {
        format!("postgres://{user}:{pass}@{}:{}/{DB}", self.host, self.port)
    }
    fn reader(&self) -> String {
        self.url("secrets_reader", "readerpw")
    }
    fn writer(&self) -> String {
        self.url("secrets_writer", "writerpw")
    }
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

async fn setup(admin_url: &str) -> Fixture {
    let opts: PgConnectOptions = admin_url.parse().expect("SECRETS_TEST_ADMIN_URL");
    let (host, port) = (opts.get_host().to_string(), opts.get_port());
    let mut conn = opts.clone().connect().await.expect("connect as admin");

    for sql in [
        format!("DROP DATABASE IF EXISTS {DB} WITH (FORCE)"),
        format!("CREATE DATABASE {DB}"),
    ] {
        sqlx::raw_sql(AssertSqlSafe(sql)).execute(&mut conn).await.unwrap();
    }
    for role in ["app_user", "secrets_reader", "secrets_writer", "secrets_owner"] {
        sqlx::raw_sql(AssertSqlSafe(format!("DROP ROLE IF EXISTS {role}"))).execute(&mut conn).await.unwrap();
    }

    let mut db = opts.database(DB).connect().await.unwrap();
    sqlx::raw_sql(include_str!("../migrations/001_secrets.sql")).execute(&mut db).await.unwrap();
    sqlx::raw_sql(
        "ALTER ROLE secrets_reader PASSWORD 'readerpw';
         ALTER ROLE secrets_writer PASSWORD 'writerpw';
         CREATE ROLE app_user LOGIN PASSWORD 'apppw';",
    )
    .execute(&mut db)
    .await
    .unwrap();

    Fixture { host, port, admin_url: replace_db(admin_url, DB) }
}

/// Swap the database name at the end of a URL (ignoring any query string).
fn replace_db(url: &str, db: &str) -> String {
    let (base, query) = url.split_once('?').map_or((url, ""), |(b, q)| (b, q));
    let base = base.rsplit_once('/').map_or(base, |(b, _)| b);
    if query.is_empty() { format!("{base}/{db}") } else { format!("{base}/{db}?{query}") }
}

fn fixture() -> Option<&'static Fixture> {
    static FX: OnceLock<Option<Fixture>> = OnceLock::new();
    FX.get_or_init(|| {
        let url = std::env::var("SECRETS_TEST_ADMIN_URL").ok()?;
        Some(rt().block_on(setup(&url)))
    })
    .as_ref()
}

/// Skip (pass) when no database is configured.
macro_rules! fx {
    () => {
        match fixture() {
            Some(fx) => fx,
            None => {
                eprintln!("skipped: SECRETS_TEST_ADMIN_URL is not set");
                return;
            }
        }
    };
}

/// One isolated environment (own name, own key, own cache dir) inside the shared database.
struct Env {
    fx: &'static Fixture,
    name: String,
    key: String,
    cache_dir: PathBuf,
}

impl Env {
    fn new(fx: &'static Fixture) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let name = format!("e2e{}_{n}", std::process::id());
        rt().block_on(async {
            let mut c = PgConnection::connect(&fx.admin_url).await.unwrap();
            sqlx::query("INSERT INTO secrets.environments (name) VALUES ($1)").bind(&name).execute(&mut c).await.unwrap();
        });
        let cache_dir = std::env::temp_dir().join(format!("secrets-inject-e2e-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cache_dir);
        let key = keygen();
        Self { fx, name, key, cache_dir }
    }

    /// Run the binary with writer credentials (so `set`, `unset` and `list` work).
    fn admin(&self, args: &[&str], stdin: Option<&str>) -> Output {
        self.exec(args, stdin, &self.fx.writer(), &self.key)
    }

    /// Run `run` the way a service would: reader credentials.
    fn run(&self, system: &str, extra: &[&str], cmd: &[&str]) -> Output {
        let mut args = vec!["run", "--system", system, "--env", &self.name];
        args.extend_from_slice(extra);
        args.push("--");
        args.extend_from_slice(cmd);
        self.exec(&args, None, &self.fx.reader(), &self.key)
    }

    fn exec(&self, args: &[&str], stdin: Option<&str>, db_url: &str, key: &str) -> Output {
        let mut child = Command::new(BIN)
            .args(args)
            .env("SECRETS_DB_URL", db_url)
            .env("SECRETS_KEY", key)
            .env("SECRETS_CACHE_DIR", &self.cache_dir)
            .env("SECRETS_USER", "tester")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(input) = stdin {
            child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        }
        drop(child.stdin.take());
        child.wait_with_output().unwrap()
    }

    fn set(&self, key: &str, scope: &[&str], value: &str) {
        let mut args = vec!["set", key, "--env", &self.name];
        args.extend_from_slice(scope);
        let out = self.admin(&args, Some(value));
        assert!(out.status.success(), "set {key} failed: {}", stderr(&out));
    }

    /// Echo one variable from the app's point of view.
    fn var(&self, system: &str, extra: &[&str], name: &str) -> String {
        let script = format!("printf %s \"${{{name}-<unset>}}\"");
        let out = self.run(system, extra, &["sh", "-c", &script]);
        assert!(out.status.success(), "run failed: {}", stderr(&out));
        stdout(&out)
    }

    fn sql(&self, sql: &str) {
        rt().block_on(async {
            let mut c = PgConnection::connect(&self.fx.admin_url).await.unwrap();
            sqlx::raw_sql(AssertSqlSafe(sql.to_string())).execute(&mut c).await.unwrap();
        });
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.cache_dir);
    }
}

fn keygen() -> String {
    let out = Command::new(BIN).arg("keygen").output().unwrap();
    assert!(out.status.success());
    stdout(&out).trim().to_string()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

// ---------- keygen ----------

#[test]
fn keygen_prints_a_fresh_64_char_hex_key_each_time() {
    let (a, b) = (keygen(), keygen());
    assert_eq!(a.len(), 64);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(a, b);
}

// ---------- schema and roles ----------

#[test]
fn app_user_is_locked_out_of_the_secrets_schema() {
    let fx = fx!();
    rt().block_on(async {
        let mut c = PgConnection::connect(&fx.url("app_user", "apppw")).await.unwrap();
        let err = sqlx::query("SELECT * FROM secrets.secrets").fetch_all(&mut c).await.unwrap_err();
        assert!(err.to_string().contains("permission denied for schema secrets"), "{err}");
    });
}

#[test]
fn reader_role_cannot_write() {
    let fx = fx!();
    let env = Env::new(fx);
    // `set` with reader credentials must fail at the database.
    let out = env.exec(&["set", "X", "--shared", "--env", &env.name], Some("v"), &fx.reader(), &env.key);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("permission denied"), "{}", stderr(&out));
}

#[test]
fn key_format_is_enforced_by_a_check_constraint() {
    let fx = fx!();
    let env = Env::new(fx);
    let name = env.name.clone();
    rt().block_on(async {
        let mut c = PgConnection::connect(&fx.admin_url).await.unwrap();
        let err = sqlx::query(
            "INSERT INTO secrets.secrets (environment_id, key, value, updated_by)
             SELECT id, 'lower_case', '\\x00', 'x' FROM secrets.environments WHERE name = $1",
        )
        .bind(&name)
        .execute(&mut c)
        .await
        .unwrap_err();
        assert!(err.to_string().contains("check constraint"), "{err}");
    });
}

// ---------- set / list / unset ----------

#[test]
fn set_then_run_delivers_the_value_and_hides_bootstrap_vars() {
    let env = Env::new(fx!());
    env.set("DATABASE_URL", &["--shared"], "postgres://db/app");
    env.set("STRIPE_SECRET_KEY", &["--system", "backend"], "sk_live_123");

    let out = env.run("backend", &[], &["env"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let vars = stdout(&out);
    assert!(vars.lines().any(|l| l == "DATABASE_URL=postgres://db/app"));
    assert!(vars.lines().any(|l| l == "STRIPE_SECRET_KEY=sk_live_123"));
    assert!(!vars.contains("SECRETS_KEY"), "master key leaked to the app");
    assert!(!vars.contains("SECRETS_DB_URL"), "reader credentials leaked to the app");
    assert!(stderr(&out).contains(&format!("loaded 2 secrets for backend/{}", env.name)));
}

#[test]
fn system_value_overrides_shared_and_other_systems_keep_shared() {
    let env = Env::new(fx!());
    env.set("REDIS_URL", &["--shared"], "redis://shared");
    env.set("REDIS_URL", &["--system", "worker"], "redis://worker");

    assert_eq!(env.var("worker", &[], "REDIS_URL"), "redis://worker");
    assert_eq!(env.var("backend", &[], "REDIS_URL"), "redis://shared");
}

#[test]
fn backend_only_secrets_do_not_reach_other_systems() {
    let env = Env::new(fx!());
    env.set("STRIPE_SECRET_KEY", &["--system", "backend"], "sk");
    assert_eq!(env.var("worker", &[], "STRIPE_SECRET_KEY"), "<unset>");
    assert_eq!(env.var("backend", &[], "STRIPE_SECRET_KEY"), "sk");
}

#[test]
fn public_only_loads_only_public_rows() {
    let env = Env::new(fx!());
    env.set("DATABASE_URL", &["--shared"], "private");
    env.set("NEXT_PUBLIC_APP_URL", &["--system", "frontend", "--public"], "https://example.com");

    assert_eq!(env.var("frontend", &["--public-only"], "DATABASE_URL"), "<unset>");
    assert_eq!(env.var("frontend", &["--public-only"], "NEXT_PUBLIC_APP_URL"), "https://example.com");
    // Without the flag the frontend server sees its private values too.
    assert_eq!(env.var("frontend", &[], "DATABASE_URL"), "private");
}

#[test]
fn set_reads_stdin_keeping_inner_newlines_and_equals_signs() {
    let env = Env::new(fx!());
    let pem = "-----BEGIN KEY-----\nabc==\n-----END KEY-----";
    env.set("JWT_PRIVATE_KEY", &["--shared"], &format!("{pem}\n"));
    env.set("B64", &["--shared"], "aGVsbG8=\r\n");
    assert_eq!(env.var("backend", &[], "JWT_PRIVATE_KEY"), pem);
    assert_eq!(env.var("backend", &[], "B64"), "aGVsbG8=");
}

#[test]
fn set_twice_updates_in_place_and_keeps_the_description() {
    let env = Env::new(fx!());
    env.set("API_TOKEN", &["--shared", "--description", "the token"], "one");
    env.set("API_TOKEN", &["--shared"], "two");
    assert_eq!(env.var("backend", &[], "API_TOKEN"), "two");

    let out = env.admin(&["list", "--env", &env.name], None);
    assert_eq!(stdout(&out).lines().filter(|l| l.starts_with("API_TOKEN")).count(), 1);
    let desc = rt().block_on(async {
        let mut c = PgConnection::connect(&env.fx.admin_url).await.unwrap();
        sqlx::query("SELECT description FROM secrets.secrets s JOIN secrets.environments e ON e.id = s.environment_id WHERE e.name = $1")
            .bind(&env.name)
            .fetch_one(&mut c)
            .await
            .unwrap()
            .get::<Option<String>, _>("description")
    });
    assert_eq!(desc.as_deref(), Some("the token"));
}

#[test]
fn set_without_public_flag_makes_a_public_secret_private_again() {
    let env = Env::new(fx!());
    env.set("FLAG", &["--system", "frontend", "--public"], "v");
    assert_eq!(env.var("frontend", &["--public-only"], "FLAG"), "v");
    env.set("FLAG", &["--system", "frontend"], "v");
    assert_eq!(env.var("frontend", &["--public-only"], "FLAG"), "<unset>");
}

#[test]
fn set_rejects_bad_names_and_empty_values() {
    let env = Env::new(fx!());
    let out = env.admin(&["set", "lower", "--shared", "--env", &env.name], Some("v"));
    assert!(!out.status.success());
    assert!(stderr(&out).contains("UPPER_SNAKE_CASE"));

    let out = env.admin(&["set", "EMPTY", "--shared", "--env", &env.name], Some("\n"));
    assert!(!out.status.success());
    assert!(stderr(&out).contains("empty value"));
}

#[test]
fn set_refuses_a_different_key_once_values_exist() {
    let env = Env::new(fx!());
    env.set("A", &["--shared"], "1");
    let other = keygen();
    let out = env.exec(&["set", "B", "--shared", "--env", &env.name], Some("2"), &env.fx.writer(), &other);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("does not match the key already used"), "{}", stderr(&out));
}

#[test]
fn set_rejects_unknown_system_and_environment() {
    let env = Env::new(fx!());
    let out = env.admin(&["set", "A", "--system", "nope", "--env", &env.name], Some("1"));
    assert!(stderr(&out).contains("unknown system `nope`"), "{}", stderr(&out));
    let out = env.admin(&["set", "A", "--shared", "--env", "nope"], Some("1"));
    assert!(stderr(&out).contains("unknown environment `nope`"), "{}", stderr(&out));
}

#[test]
fn list_shows_metadata_and_never_values() {
    let env = Env::new(fx!());
    env.set("DATABASE_URL", &["--shared"], "super-secret-value");
    env.set("REDIS_URL", &["--system", "worker", "--public"], "another-secret");

    let out = env.admin(&["list", "--env", &env.name], None);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.starts_with("KEY"), "{text}");
    assert!(text.contains("DATABASE_URL") && text.contains("shared") && text.contains("tester"));
    assert!(text.contains("REDIS_URL") && text.contains("worker") && text.contains("yes"));
    assert!(!text.contains("super-secret-value") && !text.contains("another-secret"));
}

#[test]
fn list_with_system_shows_what_that_system_receives() {
    let env = Env::new(fx!());
    env.set("SHARED_ONE", &["--shared"], "1");
    env.set("BACKEND_ONE", &["--system", "backend"], "2");
    env.set("WORKER_ONE", &["--system", "worker"], "3");

    let text = stdout(&env.admin(&["list", "--env", &env.name, "--system", "backend"], None));
    assert!(text.contains("SHARED_ONE") && text.contains("BACKEND_ONE"));
    assert!(!text.contains("WORKER_ONE"));

    let out = env.admin(&["list", "--env", &env.name, "--system", "nope"], None);
    assert!(stderr(&out).contains("unknown system `nope`"));
}

#[test]
fn unset_removes_the_secret_and_complains_when_missing() {
    let env = Env::new(fx!());
    env.set("GONE", &["--shared"], "v");
    let out = env.admin(&["unset", "GONE", "--shared", "--env", &env.name], None);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(env.var("backend", &[], "GONE"), "<unset>");

    let out = env.admin(&["unset", "GONE", "--shared", "--env", &env.name], None);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("GONE not found"));
}

#[test]
fn unset_only_removes_the_requested_scope() {
    let env = Env::new(fx!());
    env.set("REDIS_URL", &["--shared"], "shared");
    env.set("REDIS_URL", &["--system", "worker"], "worker");
    let out = env.admin(&["unset", "REDIS_URL", "--system", "worker", "--env", &env.name], None);
    assert!(out.status.success());
    assert_eq!(env.var("worker", &[], "REDIS_URL"), "shared");
}

#[test]
fn environments_are_isolated_from_each_other() {
    let fx = fx!();
    let (a, b) = (Env::new(fx), Env::new(fx));
    a.set("ONLY_A", &["--shared"], "a");
    assert_eq!(a.var("backend", &[], "ONLY_A"), "a");
    assert_eq!(b.var("backend", &[], "ONLY_A"), "<unset>");
}

// ---------- run: process semantics ----------

#[test]
fn the_app_replaces_the_process_keeping_the_same_pid() {
    let env = Env::new(fx!());
    env.set("A", &["--shared"], "1");
    let child = Command::new(BIN)
        .args(["run", "--system", "backend", "--env", &env.name, "--", "sh", "-c", "echo $$"])
        .env("SECRETS_DB_URL", env.fx.reader())
        .env("SECRETS_KEY", &env.key)
        .env("SECRETS_CACHE_DIR", &env.cache_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    let out = child.wait_with_output().unwrap();
    assert_eq!(stdout(&out).trim(), pid.to_string());
}

#[test]
fn the_apps_exit_code_is_preserved() {
    let env = Env::new(fx!());
    let out = env.run("backend", &[], &["sh", "-c", "exit 7"]);
    assert_eq!(out.status.code(), Some(7));
}

#[test]
fn a_command_that_cannot_start_is_reported() {
    let env = Env::new(fx!());
    let out = env.run("backend", &[], &["/nonexistent/binary"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("could not start `/nonexistent/binary`"), "{}", stderr(&out));
}

#[test]
fn arguments_after_double_dash_reach_the_app_untouched() {
    let env = Env::new(fx!());
    let out = env.run("backend", &[], &["sh", "-c", "printf '%s|' \"$@\"", "sh", "--env", "--system", "a b"]);
    assert_eq!(stdout(&out), "--env|--system|a b|");
}

// ---------- run: cache fallback ----------

fn dead_url() -> String {
    format!("postgres://secrets_reader:readerpw@127.0.0.1:1/{DB}")
}

#[test]
fn run_writes_a_cache_and_uses_it_when_postgres_is_down() {
    let env = Env::new(fx!());
    env.set("DATABASE_URL", &["--shared"], "from-db");
    assert!(env.run("backend", &[], &["true"]).status.success());

    let cache = env.cache_dir.join(format!("backend.{}.cache", env.name));
    assert!(cache.exists());
    assert!(!std::fs::read(&cache).unwrap().windows(7).any(|w| w == b"from-db"), "cache is plaintext");

    let out = env.exec(
        &["run", "--system", "backend", "--env", &env.name, "--", "sh", "-c", "printf %s \"$DATABASE_URL\""],
        None,
        &dead_url(),
        &env.key,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "from-db");
    let err = stderr(&out);
    assert!(err.contains("database unavailable") && err.contains("trying cache"), "{err}");
    assert!(err.contains("from a cache") && err.contains("old"), "{err}");
}

#[test]
fn no_cache_flag_neither_writes_nor_reads_the_cache() {
    let env = Env::new(fx!());
    env.set("A", &["--shared"], "1");
    assert!(env.run("backend", &["--no-cache"], &["true"]).status.success());
    assert!(!env.cache_dir.exists(), "--no-cache wrote a cache");

    assert!(env.run("backend", &[], &["true"]).status.success()); // now a cache exists
    let out = env.exec(
        &["run", "--system", "backend", "--env", &env.name, "--no-cache", "--", "true"],
        None,
        &dead_url(),
        &env.key,
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--no-cache is set"), "{}", stderr(&out));
}

#[test]
fn postgres_down_with_no_cache_yet_fails() {
    let env = Env::new(fx!());
    let out = env.exec(&["run", "--system", "backend", "--env", &env.name, "--", "true"], None, &dead_url(), &env.key);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no usable cache either"), "{}", stderr(&out));
}

#[test]
fn a_tampered_cache_is_refused() {
    let env = Env::new(fx!());
    env.set("A", &["--shared"], "1");
    assert!(env.run("backend", &[], &["true"]).status.success());
    let cache = env.cache_dir.join(format!("backend.{}.cache", env.name));
    let mut raw = std::fs::read(&cache).unwrap();
    raw[30] ^= 0xff;
    std::fs::write(&cache, raw).unwrap();

    let out = env.exec(&["run", "--system", "backend", "--env", &env.name, "--", "true"], None, &dead_url(), &env.key);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("cache could not be decrypted"), "{}", stderr(&out));
}

#[test]
fn a_connect_timeout_falls_back_to_the_cache_after_about_five_seconds() {
    let env = Env::new(fx!());
    env.set("A", &["--shared"], "1");
    assert!(env.run("backend", &[], &["true"]).status.success());

    // Accepts TCP connections but never speaks Postgres: only the timeout can end this.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("postgres://secrets_reader:readerpw@127.0.0.1:{}/{DB}", listener.local_addr().unwrap().port());
    let started = Instant::now();
    let out = env.exec(&["run", "--system", "backend", "--env", &env.name, "--", "true"], None, &url, &env.key);
    let took = started.elapsed().as_secs_f32();

    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).contains("timed out connecting to Postgres"), "{}", stderr(&out));
    assert!((4.5..9.0).contains(&took), "took {took}s");
}

// ---------- run: misconfiguration must fail loudly, never use the cache ----------

#[test]
fn wrong_secrets_key_fails_instead_of_using_the_cache() {
    let env = Env::new(fx!());
    env.set("DATABASE_URL", &["--shared"], "v");
    assert!(env.run("backend", &[], &["true"]).status.success());

    let out = env.exec(
        &["run", "--system", "backend", "--env", &env.name, "--", "true"],
        None,
        &env.fx.reader(),
        &keygen(),
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("could not decrypt DATABASE_URL"), "{}", stderr(&out));
    assert!(!stderr(&out).contains("trying cache"));
}

#[test]
fn unknown_system_or_environment_fails_immediately() {
    let env = Env::new(fx!());
    env.set("A", &["--shared"], "1");
    assert!(env.run("backend", &[], &["true"]).status.success()); // cache exists, must not be used

    let out = env.run("api", &[], &["true"]);
    assert!(stderr(&out).contains("unknown system `api`"), "{}", stderr(&out));
    assert!(!out.status.success());

    let out = env.exec(&["run", "--system", "backend", "--env", "nope", "--", "true"], None, &env.fx.reader(), &env.key);
    assert!(stderr(&out).contains("unknown environment `nope`"), "{}", stderr(&out));
    assert!(!out.status.success());
}

#[test]
fn wrong_database_password_fails_instead_of_using_the_cache() {
    let env = Env::new(fx!());
    env.set("A", &["--shared"], "1");
    assert!(env.run("backend", &[], &["true"]).status.success());

    let bad = env.fx.url("secrets_reader", "wrong-password");
    let out = env.exec(&["run", "--system", "backend", "--env", &env.name, "--", "true"], None, &bad, &env.key);
    assert!(!out.status.success());
    assert!(!stderr(&out).contains("trying cache"), "{}", stderr(&out));
}

#[test]
fn missing_permission_fails_instead_of_using_the_cache() {
    let env = Env::new(fx!());
    env.set("A", &["--shared"], "1");
    assert!(env.run("backend", &[], &["true"]).status.success());

    let app = env.fx.url("app_user", "apppw");
    let out = env.exec(&["run", "--system", "backend", "--env", &env.name, "--", "true"], None, &app, &env.key);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("permission denied"), "{}", stderr(&out));
    assert!(!stderr(&out).contains("trying cache"));
}

#[test]
fn missing_bootstrap_variables_are_reported() {
    let env = Env::new(fx!());
    let out = Command::new(BIN)
        .args(["run", "--system", "backend", "--env", &env.name, "--", "true"])
        .env_remove("SECRETS_KEY")
        .env_remove("SECRETS_DB_URL")
        .output()
        .unwrap();
    assert!(stderr(&out).contains("SECRETS_KEY is not set"), "{}", stderr(&out));

    let out = Command::new(BIN)
        .args(["run", "--system", "backend", "--env", &env.name, "--", "true"])
        .env("SECRETS_KEY", &env.key)
        .env_remove("SECRETS_DB_URL")
        .output()
        .unwrap();
    assert!(stderr(&out).contains("SECRETS_DB_URL is not set"), "{}", stderr(&out));
}

#[test]
fn an_invalid_database_url_is_a_config_error() {
    let env = Env::new(fx!());
    let out = env.exec(&["run", "--system", "backend", "--env", &env.name, "--", "true"], None, "not a url", &env.key);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not a valid Postgres URL"), "{}", stderr(&out));
}

// ---------- encryption binding ----------

#[test]
fn a_ciphertext_moved_to_another_row_refuses_to_decrypt() {
    let env = Env::new(fx!());
    env.set("LOW_VALUE", &["--shared"], "boring");
    env.set("STRIPE_SECRET_KEY", &["--shared"], "sk_live");
    // An attacker with write access copies one row's ciphertext over the other.
    env.sql(&format!(
        "UPDATE secrets.secrets SET value = (SELECT value FROM secrets.secrets s2 WHERE s2.key = 'LOW_VALUE'
                                             AND s2.environment_id = secrets.secrets.environment_id)
         WHERE key = 'STRIPE_SECRET_KEY'
           AND environment_id = (SELECT id FROM secrets.environments WHERE name = '{}')",
        env.name
    ));
    let out = env.run("backend", &[], &["true"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("could not decrypt STRIPE_SECRET_KEY"), "{}", stderr(&out));
}

#[test]
fn values_are_stored_encrypted() {
    let env = Env::new(fx!());
    env.set("PLAINTEXT_CHECK", &["--shared"], "needle-in-haystack");
    let hit = rt().block_on(async {
        let mut c = PgConnection::connect(&env.fx.admin_url).await.unwrap();
        sqlx::query("SELECT count(*) AS n FROM secrets.secrets WHERE position('needle-in-haystack'::bytea in value) > 0")
            .fetch_one(&mut c)
            .await
            .unwrap()
            .get::<i64, _>("n")
    });
    assert_eq!(hit, 0);
}

#[test]
fn secret_values_never_appear_on_stdout_or_stderr_of_the_tool() {
    let env = Env::new(fx!());
    let out = env.admin(&["set", "TOKEN", "--shared", "--env", &env.name], Some("topsecretvalue"));
    assert!(!stdout(&out).contains("topsecretvalue") && !stderr(&out).contains("topsecretvalue"));
    let out = env.run("backend", &[], &["true"]);
    assert!(!stdout(&out).contains("topsecretvalue") && !stderr(&out).contains("topsecretvalue"));
}
