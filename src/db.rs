use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};

use crate::config::AppConfig;

const CONNECTION_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct Database {
    path: PathBuf,
    open_flags: OpenFlags,
    busy_timeout: Duration,
}

impl Database {
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

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::Database;
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

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();

        std::env::temp_dir().join(format!("secret-rs-{prefix}-{unique}"))
    }

    fn cleanup_temp_dir(path: &std::path::Path) {
        let _ = fs::remove_dir_all(path);
    }
}
