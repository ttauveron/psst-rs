use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::config::AppConfig;

const CONNECTION_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  ciphertext TEXT NOT NULL,
  nonce TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  delete_token_hash TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  requester_ip_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_secrets_expires_at
ON secrets(expires_at);

CREATE INDEX IF NOT EXISTS idx_secrets_consumed_at
ON secrets(consumed_at);

CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (key, bucket)
);
"#;

#[derive(Debug, Clone)]
pub struct Database {
    path: PathBuf,
    open_flags: OpenFlags,
    busy_timeout: Duration,
}

impl Database {
    pub fn bootstrap(config: &AppConfig) -> Result<Self> {
        let database = Self::connect(config)?;
        database.initialize_schema()?;
        Ok(database)
    }

    pub fn connect(config: &AppConfig) -> Result<Self> {
        let database = Self {
            path: config.database_path.clone(),
            open_flags: OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            busy_timeout: CONNECTION_BUSY_TIMEOUT,
        };

        database.ensure_parent_directory()?;
        let connection = database.open_connection()?;
        drop(connection);

        Ok(database)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn initialize_schema(&self) -> Result<()> {
        let connection = self.open_connection()?;
        connection
            .execute_batch(SCHEMA_SQL)
            .context("failed to initialize SQLite schema")?;

        Ok(())
    }

    pub fn open_connection(&self) -> Result<Connection> {
        let connection = Connection::open_with_flags(&self.path, self.open_flags)
            .with_context(|| format!("failed to open SQLite database at {}", self.path.display()))?;

        self.configure_connection(&connection)?;
        Ok(connection)
    }

    fn ensure_parent_directory(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "failed to create parent directory for SQLite database: {}",
                        parent.display()
                    )
                })?;
            }
        }

        Ok(())
    }

    fn configure_connection(&self, connection: &Connection) -> Result<()> {
        connection
            .busy_timeout(self.busy_timeout)
            .context("failed to configure SQLite busy timeout")?;

        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = NORMAL;",
            )
            .context("failed to configure SQLite connection pragmas")?;

        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRecord {
    pub id: String,
    pub ciphertext: String,
    pub nonce: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub consumed_at: Option<i64>,
    pub delete_token_hash: String,
    pub size_bytes: u64,
    pub requester_ip_hash: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSecretRecord {
    pub id: String,
    pub ciphertext: String,
    pub nonce: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub delete_token_hash: String,
    pub size_bytes: u64,
    pub requester_ip_hash: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SecretStore {
    database: Database,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveSecretStats {
    pub active_secret_count: u64,
    pub active_storage_bytes: u64,
}

#[allow(dead_code)]
impl SecretStore {
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    pub fn insert_secret(&self, secret: &NewSecretRecord) -> Result<()> {
        let connection = self.database.open_connection()?;
        connection
            .execute(
                "INSERT INTO secrets (
                    id,
                    ciphertext,
                    nonce,
                    created_at,
                    expires_at,
                    consumed_at,
                    delete_token_hash,
                    size_bytes,
                    requester_ip_hash
                ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8)",
                params![
                    &secret.id,
                    &secret.ciphertext,
                    &secret.nonce,
                    secret.created_at,
                    secret.expires_at,
                    &secret.delete_token_hash,
                    i64::try_from(secret.size_bytes).context("secret size exceeds SQLite integer range")?,
                    &secret.requester_ip_hash,
                ],
            )
            .context("failed to insert secret record")?;

        Ok(())
    }

    pub fn get_secret_by_id(&self, secret_id: &str) -> Result<Option<SecretRecord>> {
        let connection = self.database.open_connection()?;
        connection
            .query_row(
                "SELECT
                    id,
                    ciphertext,
                    nonce,
                    created_at,
                    expires_at,
                    consumed_at,
                    delete_token_hash,
                    size_bytes,
                    requester_ip_hash
                 FROM secrets
                 WHERE id = ?1",
                [secret_id],
                map_secret_row,
            )
            .optional()
            .context("failed to load secret record")
    }

    pub fn delete_secret_by_id_and_token_hash(
        &self,
        secret_id: &str,
        delete_token_hash: &str,
    ) -> Result<bool> {
        let connection = self.database.open_connection()?;
        let deleted_rows = connection
            .execute(
                "DELETE FROM secrets
                 WHERE id = ?1 AND delete_token_hash = ?2",
                [secret_id, delete_token_hash],
            )
            .context("failed to delete secret record")?;

        Ok(deleted_rows == 1)
    }

    pub fn delete_expired_secrets(&self, now_timestamp: i64) -> Result<usize> {
        let connection = self.database.open_connection()?;
        connection
            .execute(
                "DELETE FROM secrets
                 WHERE expires_at <= ?1",
                [now_timestamp],
            )
            .context("failed to purge expired secrets")
    }

    pub fn active_secret_stats(&self, now_timestamp: i64) -> Result<ActiveSecretStats> {
        let connection = self.database.open_connection()?;
        connection
            .query_row(
                "SELECT
                    COUNT(*),
                    COALESCE(SUM(size_bytes), 0)
                 FROM secrets
                 WHERE expires_at > ?1
                   AND consumed_at IS NULL",
                [now_timestamp],
                |row| {
                    let active_secret_count: i64 = row.get(0)?;
                    let active_storage_bytes: i64 = row.get(1)?;

                    Ok(ActiveSecretStats {
                        active_secret_count: u64::try_from(active_secret_count).map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Integer,
                                Box::new(error),
                            )
                        })?,
                        active_storage_bytes: u64::try_from(active_storage_bytes).map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                1,
                                rusqlite::types::Type::Integer,
                                Box::new(error),
                            )
                        })?,
                    })
                },
            )
            .context("failed to load active secret stats")
    }

    // v1 strategy: consume a secret by deleting it immediately in the same
    // transaction that reads it, rather than marking `consumed_at` first.
    pub fn consume_unexpired_secret_by_id(
        &self,
        secret_id: &str,
        now_timestamp: i64,
    ) -> Result<Option<SecretRecord>> {
        self.with_immediate_transaction(|connection| {
            let secret = connection
                .query_row(
                    "SELECT
                        id,
                        ciphertext,
                        nonce,
                        created_at,
                        expires_at,
                        consumed_at,
                        delete_token_hash,
                        size_bytes,
                        requester_ip_hash
                     FROM secrets
                     WHERE id = ?1
                       AND expires_at > ?2
                       AND consumed_at IS NULL",
                    params![secret_id, now_timestamp],
                    map_secret_row,
                )
                .optional()
                .context("failed to load secret for consumption")?;

            let Some(secret) = secret else {
                return Ok(None);
            };

            let deleted_rows = connection
                .execute("DELETE FROM secrets WHERE id = ?1", [secret_id])
                .context("failed to delete consumed secret")?;

            ensure!(
                deleted_rows == 1,
                "expected to delete exactly one secret during consumption"
            );

            Ok(Some(secret))
        })
    }

    pub fn with_immediate_transaction<T, F>(&self, operation: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let mut connection = self.database.open_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("failed to open immediate SQLite transaction")?;

        let result = operation(&transaction)?;
        transaction
            .commit()
            .context("failed to commit SQLite transaction")?;

        Ok(result)
    }
}

#[allow(dead_code)]
fn map_secret_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretRecord> {
    let size_bytes: i64 = row.get(7)?;

    Ok(SecretRecord {
        id: row.get(0)?,
        ciphertext: row.get(1)?,
        nonce: row.get(2)?,
        created_at: row.get(3)?,
        expires_at: row.get(4)?,
        consumed_at: row.get(5)?,
        delete_token_hash: row.get(6)?,
        size_bytes: u64::try_from(size_bytes).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                7,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?,
        requester_ip_hash: row.get(8)?,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier},
        thread,
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use anyhow::Context;
    use rusqlite::Connection;
    use rusqlite::params;

    use super::{ActiveSecretStats, Database, NewSecretRecord, SecretStore};
    use crate::config::AppConfig;

    #[test]
    fn connect_creates_parent_directory_and_opens_database() {
        let mut config = AppConfig::default();
        let temp_root = unique_temp_dir("open-db");
        let database_path = temp_root.join("nested").join("secrets.db");
        config.database_path = database_path.clone();

        let database = Database::connect(&config).expect("database should open");
        let connection = database
            .open_connection()
            .expect("database connection should open");

        let value: i64 = connection
            .query_row("SELECT 1", [], |row| row.get(0))
            .expect("query should succeed");

        assert_eq!(value, 1);
        assert!(database_path.parent().expect("parent should exist").exists());
        assert_eq!(database.path(), database_path.as_path());

        cleanup_temp_dir(&temp_root);
    }

    #[test]
    fn opened_connections_apply_expected_pragmas() {
        let mut config = AppConfig::default();
        let temp_root = unique_temp_dir("sqlite-pragmas");
        config.database_path = temp_root.join("secrets.db");

        let database = Database::connect(&config).expect("database should open");
        let connection = database
            .open_connection()
            .expect("database connection should open");

        let foreign_keys_enabled: i64 = connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .expect("pragma should be readable");
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("pragma should be readable");

        assert_eq!(foreign_keys_enabled, 1);
        assert_eq!(journal_mode, "wal");

        cleanup_temp_dir(&temp_root);
    }

    #[test]
    fn initialize_schema_creates_expected_tables_and_indexes() {
        let mut config = AppConfig::default();
        let temp_root = unique_temp_dir("sqlite-schema");
        config.database_path = temp_root.join("secrets.db");

        let database = Database::connect(&config).expect("database should open");
        database
            .initialize_schema()
            .expect("schema initialization should succeed");

        let connection = database
            .open_connection()
            .expect("database connection should open");

        assert!(schema_object_exists(&connection, "table", "secrets"));
        assert!(schema_object_exists(&connection, "table", "rate_limits"));
        assert!(schema_object_exists(
            &connection,
            "index",
            "idx_secrets_expires_at"
        ));
        assert!(schema_object_exists(
            &connection,
            "index",
            "idx_secrets_consumed_at"
        ));

        cleanup_temp_dir(&temp_root);
    }

    #[test]
    fn initialize_schema_is_idempotent() {
        let mut config = AppConfig::default();
        let temp_root = unique_temp_dir("sqlite-idempotent");
        config.database_path = temp_root.join("secrets.db");

        let database = Database::connect(&config).expect("database should open");
        database
            .initialize_schema()
            .expect("first schema initialization should succeed");
        database
            .initialize_schema()
            .expect("second schema initialization should succeed");

        let connection = database
            .open_connection()
            .expect("database connection should open");

        assert_eq!(count_schema_objects(&connection, "table", "secrets"), 1);
        assert_eq!(count_schema_objects(&connection, "table", "rate_limits"), 1);
        assert_eq!(
            count_schema_objects(&connection, "index", "idx_secrets_expires_at"),
            1
        );
        assert_eq!(
            count_schema_objects(&connection, "index", "idx_secrets_consumed_at"),
            1
        );

        cleanup_temp_dir(&temp_root);
    }

    #[test]
    fn bootstrap_opens_database_and_initializes_schema() {
        let mut config = AppConfig::default();
        let temp_root = unique_temp_dir("sqlite-bootstrap");
        config.database_path = temp_root.join("nested").join("secrets.db");

        let database = Database::bootstrap(&config).expect("database bootstrap should succeed");
        let connection = database
            .open_connection()
            .expect("database connection should open");

        assert!(schema_object_exists(&connection, "table", "secrets"));
        assert!(schema_object_exists(&connection, "table", "rate_limits"));
        assert_eq!(database.path(), config.database_path.as_path());

        cleanup_temp_dir(&temp_root);
    }

    #[test]
    fn secret_store_can_insert_and_fetch_secret() {
        let (temp_root, store) = setup_secret_store("secret-store-insert");
        let new_secret = sample_secret("secret-1", 1_700_000_000, 1_700_086_400);

        store
            .insert_secret(&new_secret)
            .expect("secret insertion should succeed");

        let stored = store
            .get_secret_by_id(&new_secret.id)
            .expect("secret lookup should succeed")
            .expect("secret should exist");

        assert_eq!(stored.id, new_secret.id);
        assert_eq!(stored.ciphertext, new_secret.ciphertext);
        assert_eq!(stored.nonce, new_secret.nonce);
        assert_eq!(stored.created_at, new_secret.created_at);
        assert_eq!(stored.expires_at, new_secret.expires_at);
        assert_eq!(stored.consumed_at, None);
        assert_eq!(stored.delete_token_hash, new_secret.delete_token_hash);
        assert_eq!(stored.size_bytes, new_secret.size_bytes);
        assert_eq!(stored.requester_ip_hash, new_secret.requester_ip_hash);

        cleanup_temp_dir(&temp_root);
    }

    #[test]
    fn secret_store_deletes_only_matching_delete_token_hash() {
        let (temp_root, store) = setup_secret_store("secret-store-delete");
        let new_secret = sample_secret("secret-2", 1_700_000_000, 1_700_086_400);

        store
            .insert_secret(&new_secret)
            .expect("secret insertion should succeed");

        let deleted = store
            .delete_secret_by_id_and_token_hash(&new_secret.id, "wrong-hash")
            .expect("delete with wrong hash should not fail");
        assert!(!deleted);
        assert!(
            store
                .get_secret_by_id(&new_secret.id)
                .expect("secret lookup should succeed")
                .is_some()
        );

        let deleted = store
            .delete_secret_by_id_and_token_hash(&new_secret.id, &new_secret.delete_token_hash)
            .expect("delete with matching hash should succeed");
        assert!(deleted);
        assert!(
            store
                .get_secret_by_id(&new_secret.id)
                .expect("secret lookup should succeed")
                .is_none()
        );

        cleanup_temp_dir(&temp_root);
    }

    #[test]
    fn secret_store_can_purge_expired_secrets() {
        let (temp_root, store) = setup_secret_store("secret-store-purge");
        let expired_secret = sample_secret("secret-expired", 1_700_000_000, 100);
        let active_secret = sample_secret("secret-active", 1_700_000_000, 10_000);

        store
            .insert_secret(&expired_secret)
            .expect("expired secret insertion should succeed");
        store
            .insert_secret(&active_secret)
            .expect("active secret insertion should succeed");

        let deleted_rows = store
            .delete_expired_secrets(500)
            .expect("purge should succeed");

        assert_eq!(deleted_rows, 1);
        assert!(
            store
                .get_secret_by_id(&expired_secret.id)
                .expect("expired secret lookup should succeed")
                .is_none()
        );
        assert!(
            store
                .get_secret_by_id(&active_secret.id)
                .expect("active secret lookup should succeed")
                .is_some()
        );

        cleanup_temp_dir(&temp_root);
    }

    #[test]
    fn active_secret_stats_ignore_expired_secrets() {
        let (temp_root, store) = setup_secret_store("secret-store-stats");
        let now_timestamp = 1_700_000_000;
        let active_secret = sample_secret("secret-stats-active", now_timestamp, now_timestamp + 600);
        let expired_secret = sample_secret("secret-stats-expired", now_timestamp, now_timestamp - 1);

        store
            .insert_secret(&active_secret)
            .expect("active secret insertion should succeed");
        store
            .insert_secret(&expired_secret)
            .expect("expired secret insertion should succeed");

        let stats = store
            .active_secret_stats(now_timestamp)
            .expect("active secret stats should load");

        assert_eq!(
            stats,
            ActiveSecretStats {
                active_secret_count: 1,
                active_storage_bytes: active_secret.size_bytes,
            }
        );

        cleanup_temp_dir(&temp_root);
    }

    #[test]
    fn secret_store_consumes_secret_atomically_by_deleting_it() {
        let (temp_root, store) = setup_secret_store("secret-store-consume");
        let new_secret = sample_secret("secret-consume", 1_700_000_000, 1_700_086_400);

        store
            .insert_secret(&new_secret)
            .expect("secret insertion should succeed");

        let consumed = store
            .consume_unexpired_secret_by_id(&new_secret.id, 1_700_000_100)
            .expect("secret consumption should succeed")
            .expect("secret should be consumed");

        assert_eq!(consumed.id, new_secret.id);
        assert_eq!(consumed.ciphertext, new_secret.ciphertext);
        assert_eq!(consumed.nonce, new_secret.nonce);
        assert_eq!(consumed.delete_token_hash, new_secret.delete_token_hash);
        assert!(
            store
                .get_secret_by_id(&new_secret.id)
                .expect("secret lookup should succeed")
                .is_none()
        );

        cleanup_temp_dir(&temp_root);
    }

    #[test]
    fn secret_store_returns_none_when_consuming_same_secret_twice() {
        let (temp_root, store) = setup_secret_store("secret-store-consume-twice");
        let new_secret = sample_secret("secret-consume-twice", 1_700_000_000, 1_700_086_400);

        store
            .insert_secret(&new_secret)
            .expect("secret insertion should succeed");

        let first = store
            .consume_unexpired_secret_by_id(&new_secret.id, 1_700_000_100)
            .expect("first consume should succeed");
        let second = store
            .consume_unexpired_secret_by_id(&new_secret.id, 1_700_000_101)
            .expect("second consume should succeed");

        assert!(first.is_some());
        assert!(second.is_none());

        cleanup_temp_dir(&temp_root);
    }

    #[test]
    fn secret_store_allows_exactly_one_concurrent_consumer() {
        let (temp_root, store) = setup_secret_store("secret-store-concurrent-consume");
        let new_secret = sample_secret("secret-concurrent-consume", 1_700_000_000, 1_700_086_400);

        store
            .insert_secret(&new_secret)
            .expect("secret insertion should succeed");

        let barrier = Arc::new(Barrier::new(3));
        let first_store = store.clone();
        let second_store = store.clone();
        let first_barrier = barrier.clone();
        let second_barrier = barrier.clone();
        let secret_id = new_secret.id.clone();

        let first_thread = thread::spawn(move || {
            first_barrier.wait();
            first_store
                .consume_unexpired_secret_by_id(&secret_id, 1_700_000_100)
                .expect("first concurrent consume should succeed")
                .is_some()
        });

        let second_secret_id = new_secret.id.clone();
        let second_thread = thread::spawn(move || {
            second_barrier.wait();
            second_store
                .consume_unexpired_secret_by_id(&second_secret_id, 1_700_000_100)
                .expect("second concurrent consume should succeed")
                .is_some()
        });

        barrier.wait();

        let first_succeeded = first_thread
            .join()
            .expect("first concurrent consumer should not panic");
        let second_succeeded = second_thread
            .join()
            .expect("second concurrent consumer should not panic");

        assert_ne!(first_succeeded, second_succeeded);
        assert!(
            store
                .get_secret_by_id(&new_secret.id)
                .expect("post-concurrency lookup should succeed")
                .is_none()
        );

        cleanup_temp_dir(&temp_root);
    }

    #[test]
    fn secret_store_does_not_consume_expired_secret() {
        let (temp_root, store) = setup_secret_store("secret-store-expired-consume");
        let expired_secret = sample_secret("secret-expired-consume", 1_700_000_000, 200);

        store
            .insert_secret(&expired_secret)
            .expect("secret insertion should succeed");

        let consumed = store
            .consume_unexpired_secret_by_id(&expired_secret.id, 500)
            .expect("consume should succeed");

        assert!(consumed.is_none());
        assert!(
            store
                .get_secret_by_id(&expired_secret.id)
                .expect("secret lookup should succeed")
                .is_some()
        );

        cleanup_temp_dir(&temp_root);
    }

    #[test]
    fn secret_store_supports_immediate_transactions() {
        let (temp_root, store) = setup_secret_store("secret-store-tx");
        let new_secret = sample_secret("secret-3", 1_700_000_000, 1_700_086_400);

        store
            .with_immediate_transaction(|connection| {
                connection
                    .execute(
                        "INSERT INTO secrets (
                            id,
                            ciphertext,
                            nonce,
                            created_at,
                            expires_at,
                            consumed_at,
                            delete_token_hash,
                            size_bytes,
                            requester_ip_hash
                        ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8)",
                        params![
                            &new_secret.id,
                            &new_secret.ciphertext,
                            &new_secret.nonce,
                            new_secret.created_at,
                            new_secret.expires_at,
                            &new_secret.delete_token_hash,
                            i64::try_from(new_secret.size_bytes)
                                .context("secret size should fit SQLite integer")?,
                            &new_secret.requester_ip_hash,
                        ],
                    )
                    .context("insert in transaction should succeed")?;

                Ok(())
            })
            .expect("immediate transaction should commit");

        assert!(
            store
                .get_secret_by_id(&new_secret.id)
                .expect("secret lookup should succeed")
                .is_some()
        );

        cleanup_temp_dir(&temp_root);
    }

    #[test]
    fn secret_store_rolls_back_immediate_transactions_on_error() {
        let (temp_root, store) = setup_secret_store("secret-store-tx-rollback");
        let new_secret = sample_secret("secret-rollback", 1_700_000_000, 1_700_086_400);

        let error = store
            .with_immediate_transaction(|connection| -> anyhow::Result<()> {
                connection
                    .execute(
                        "INSERT INTO secrets (
                            id,
                            ciphertext,
                            nonce,
                            created_at,
                            expires_at,
                            consumed_at,
                            delete_token_hash,
                            size_bytes,
                            requester_ip_hash
                        ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8)",
                        params![
                            &new_secret.id,
                            &new_secret.ciphertext,
                            &new_secret.nonce,
                            new_secret.created_at,
                            new_secret.expires_at,
                            &new_secret.delete_token_hash,
                            i64::try_from(new_secret.size_bytes)
                                .context("secret size should fit SQLite integer")?,
                            &new_secret.requester_ip_hash,
                        ],
                    )
                    .context("insert in rollback test should succeed")?;

                anyhow::bail!("force transaction rollback for test");
            })
            .expect_err("transaction should fail");

        assert!(
            error
                .to_string()
                .contains("force transaction rollback for test")
        );
        assert!(
            store
                .get_secret_by_id(&new_secret.id)
                .expect("secret lookup should succeed")
                .is_none()
        );

        cleanup_temp_dir(&temp_root);
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();

        std::env::temp_dir().join(format!("psst-rs-{prefix}-{unique}"))
    }

    fn cleanup_temp_dir(path: &std::path::Path) {
        let _ = fs::remove_dir_all(path);
    }

    fn setup_secret_store(prefix: &str) -> (std::path::PathBuf, SecretStore) {
        let mut config = AppConfig::default();
        let temp_root = unique_temp_dir(prefix);
        config.database_path = temp_root.join("secrets.db");

        let database = Database::bootstrap(&config).expect("database bootstrap should succeed");

        (temp_root, SecretStore::new(database))
    }

    fn sample_secret(id: &str, created_at: i64, expires_at: i64) -> NewSecretRecord {
        NewSecretRecord {
            id: id.to_owned(),
            ciphertext: "ciphertext".to_owned(),
            nonce: "nonce".to_owned(),
            created_at,
            expires_at,
            delete_token_hash: "delete-token-hash".to_owned(),
            size_bytes: 10,
            requester_ip_hash: Some("ip-hash".to_owned()),
        }
    }

    fn schema_object_exists(connection: &Connection, object_type: &str, name: &str) -> bool {
        count_schema_objects(connection, object_type, name) == 1
    }

    fn count_schema_objects(connection: &Connection, object_type: &str, name: &str) -> i64 {
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = ?1 AND name = ?2",
                [object_type, name],
                |row| row.get(0),
            )
            .expect("schema count query should succeed")
    }
}
