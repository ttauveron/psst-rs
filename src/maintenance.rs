use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use tracing::{info, warn};

use crate::{
    config::AppConfig,
    db::{Database, SecretStore},
    metrics::AppMetrics,
    rate_limit::RateLimitBucket,
};

const CREATE_MINUTE_BUCKETS_TO_KEEP: i64 = 120;
const CREATE_HOUR_BUCKETS_TO_KEEP: i64 = 48;
const READ_MINUTE_BUCKETS_TO_KEEP: i64 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaintenanceRunStats {
    pub expired_secrets_deleted: usize,
    pub create_minute_buckets_deleted: usize,
    pub create_hour_buckets_deleted: usize,
    pub read_minute_buckets_deleted: usize,
}

impl MaintenanceRunStats {
    pub fn total_deleted(self) -> usize {
        self.expired_secrets_deleted
            + self.create_minute_buckets_deleted
            + self.create_hour_buckets_deleted
            + self.read_minute_buckets_deleted
    }
}

pub fn spawn_periodic_maintenance(
    config: AppConfig,
    database: Database,
    metrics: Arc<AppMetrics>,
) {
    use std::sync::atomic::Ordering::Relaxed;

    let interval = Duration::from_secs(config.maintenance_interval_seconds);

    info!(
        maintenance_interval_seconds = config.maintenance_interval_seconds,
        "starting periodic maintenance loop"
    );

    tokio::spawn(async move {
        let secret_store = SecretStore::new(database);

        loop {
            tokio::time::sleep(interval).await;

            let now_timestamp = match current_timestamp() {
                Ok(now_timestamp) => now_timestamp,
                Err(error) => {
                    warn!(error = %error, "skipping maintenance run because current time is unavailable");
                    continue;
                }
            };

            match run_maintenance_pass(&secret_store, now_timestamp) {
                Ok(stats) => {
                    metrics.purge_runs.fetch_add(1, Relaxed);
                    metrics
                        .purge_deleted
                        .fetch_add(stats.expired_secrets_deleted as u64, Relaxed);
                    metrics
                        .secrets_expired
                        .fetch_add(stats.expired_secrets_deleted as u64, Relaxed);

                    if let Ok(active) = secret_store.active_secret_stats(now_timestamp) {
                        metrics
                            .active_secrets
                            .store(active.active_secret_count as i64, Relaxed);
                        metrics
                            .storage_bytes
                            .store(active.active_storage_bytes as i64, Relaxed);
                    }
                }
                Err(error) => {
                    metrics.db_errors_purge.fetch_add(1, Relaxed);
                    warn!(error = %error, "periodic maintenance run failed");
                }
            }
        }
    });
}

pub fn run_maintenance_pass(
    secret_store: &SecretStore,
    now_timestamp: i64,
) -> Result<MaintenanceRunStats> {
    let expired_secrets_deleted = secret_store.delete_expired_secrets(now_timestamp)?;
    let create_minute_buckets_deleted = purge_rate_limit_buckets(
        secret_store,
        RateLimitBucket::CreateMinute,
        now_timestamp,
        CREATE_MINUTE_BUCKETS_TO_KEEP,
    )?;
    let create_hour_buckets_deleted = purge_rate_limit_buckets(
        secret_store,
        RateLimitBucket::CreateHour,
        now_timestamp,
        CREATE_HOUR_BUCKETS_TO_KEEP,
    )?;
    let read_minute_buckets_deleted = purge_rate_limit_buckets(
        secret_store,
        RateLimitBucket::ReadMinute,
        now_timestamp,
        READ_MINUTE_BUCKETS_TO_KEEP,
    )?;

    let stats = MaintenanceRunStats {
        expired_secrets_deleted,
        create_minute_buckets_deleted,
        create_hour_buckets_deleted,
        read_minute_buckets_deleted,
    };

    if stats.total_deleted() > 0 {
        info!(
            expired_secrets_deleted = stats.expired_secrets_deleted,
            create_minute_buckets_deleted = stats.create_minute_buckets_deleted,
            create_hour_buckets_deleted = stats.create_hour_buckets_deleted,
            read_minute_buckets_deleted = stats.read_minute_buckets_deleted,
            "periodic maintenance removed expired data"
        );
    }

    Ok(stats)
}

fn purge_rate_limit_buckets(
    secret_store: &SecretStore,
    bucket_kind: RateLimitBucket,
    now_timestamp: i64,
    buckets_to_keep: i64,
) -> Result<usize> {
    let cutoff_bucket = bucket_kind.purge_cutoff_bucket(now_timestamp, buckets_to_keep);
    secret_store.delete_rate_limit_buckets_before(bucket_kind.key_prefix(), cutoff_bucket)
}

fn current_timestamp() -> Result<i64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is set before unix epoch")?;

    i64::try_from(now.as_secs()).context("current unix timestamp does not fit i64")
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use anyhow::Context;

    use super::{
        CREATE_HOUR_BUCKETS_TO_KEEP, CREATE_MINUTE_BUCKETS_TO_KEEP, READ_MINUTE_BUCKETS_TO_KEEP,
        run_maintenance_pass,
    };
    use crate::{
        config::AppConfig,
        db::{Database, NewSecretRecord, SecretStore},
        rate_limit::RateLimitBucket,
        secret::{generate_secret_reference, hash_delete_token},
    };

    #[test]
    fn maintenance_pass_removes_expired_secrets_without_touching_active_ones() {
        let (temp_root, store) = setup_secret_store("maintenance-expired-secrets");
        let expired_secret = sample_secret("expired-secret", 1_700_000_000, 100);
        let active_secret = sample_secret("active-secret", 1_700_000_000, 10_000);

        store
            .insert_secret(&expired_secret)
            .expect("expired secret insertion should succeed");
        store
            .insert_secret(&active_secret)
            .expect("active secret insertion should succeed");

        let stats = run_maintenance_pass(&store, 500).expect("maintenance pass should succeed");

        assert_eq!(stats.expired_secrets_deleted, 1);
        assert_eq!(
            store
                .get_secret_by_id(&expired_secret.id)
                .expect("expired secret lookup should succeed"),
            None
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
    fn maintenance_pass_purges_only_old_rate_limit_buckets() {
        let (temp_root, store) = setup_secret_store("maintenance-rate-limits");
        let now_timestamp = 180_000;

        let create_minute_old_bucket = RateLimitBucket::CreateMinute
            .purge_cutoff_bucket(now_timestamp, CREATE_MINUTE_BUCKETS_TO_KEEP)
            - 1;
        let create_minute_kept_bucket = create_minute_old_bucket + 1;
        let create_hour_old_bucket = RateLimitBucket::CreateHour
            .purge_cutoff_bucket(now_timestamp, CREATE_HOUR_BUCKETS_TO_KEEP)
            - 1;
        let create_hour_kept_bucket = create_hour_old_bucket + 1;
        let read_minute_old_bucket = RateLimitBucket::ReadMinute
            .purge_cutoff_bucket(now_timestamp, READ_MINUTE_BUCKETS_TO_KEEP)
            - 1;
        let read_minute_kept_bucket = read_minute_old_bucket + 1;

        let create_minute_key = RateLimitBucket::CreateMinute.key("ip-a");
        let create_hour_key = RateLimitBucket::CreateHour.key("ip-b");
        let read_minute_key = RateLimitBucket::ReadMinute.key("ip-c");

        store
            .increment_rate_limit_counter(&create_minute_key, create_minute_old_bucket)
            .expect("old create-minute bucket increment should succeed");
        store
            .increment_rate_limit_counter(&create_minute_key, create_minute_kept_bucket)
            .expect("kept create-minute bucket increment should succeed");
        store
            .increment_rate_limit_counter(&create_hour_key, create_hour_old_bucket)
            .expect("old create-hour bucket increment should succeed");
        store
            .increment_rate_limit_counter(&create_hour_key, create_hour_kept_bucket)
            .expect("kept create-hour bucket increment should succeed");
        store
            .increment_rate_limit_counter(&read_minute_key, read_minute_old_bucket)
            .expect("old read-minute bucket increment should succeed");
        store
            .increment_rate_limit_counter(&read_minute_key, read_minute_kept_bucket)
            .expect("kept read-minute bucket increment should succeed");

        let stats =
            run_maintenance_pass(&store, now_timestamp).expect("maintenance pass should succeed");

        assert_eq!(stats.create_minute_buckets_deleted, 1);
        assert_eq!(stats.create_hour_buckets_deleted, 1);
        assert_eq!(stats.read_minute_buckets_deleted, 1);
        assert_eq!(
            store
                .rate_limit_count(&create_minute_key, create_minute_old_bucket)
                .expect("old create-minute count should load"),
            0
        );
        assert_eq!(
            store
                .rate_limit_count(&create_minute_key, create_minute_kept_bucket)
                .expect("kept create-minute count should load"),
            1
        );
        assert_eq!(
            store
                .rate_limit_count(&create_hour_key, create_hour_old_bucket)
                .expect("old create-hour count should load"),
            0
        );
        assert_eq!(
            store
                .rate_limit_count(&create_hour_key, create_hour_kept_bucket)
                .expect("kept create-hour count should load"),
            1
        );
        assert_eq!(
            store
                .rate_limit_count(&read_minute_key, read_minute_old_bucket)
                .expect("old read-minute count should load"),
            0
        );
        assert_eq!(
            store
                .rate_limit_count(&read_minute_key, read_minute_kept_bucket)
                .expect("kept read-minute count should load"),
            1
        );

        cleanup_temp_dir(&temp_root);
    }

    #[test]
    fn database_bootstrap_does_not_purge_secrets_on_restart() {
        let temp_root = unique_temp_dir("maintenance-restart");
        let mut config = AppConfig::default();
        config.database_path = temp_root.join("secrets.db");

        let database = Database::bootstrap(&config).expect("database bootstrap should succeed");
        let store = SecretStore::new(database.clone());
        let expired_secret = sample_secret("restart-expired", 1_700_000_000, 100);
        let active_secret = sample_secret("restart-active", 1_700_000_000, 10_000);

        store
            .insert_secret(&expired_secret)
            .expect("expired secret insertion should succeed");
        store
            .insert_secret(&active_secret)
            .expect("active secret insertion should succeed");

        let restarted_database =
            Database::bootstrap(&config).expect("database restart bootstrap should succeed");
        let restarted_store = SecretStore::new(restarted_database);

        assert!(
            restarted_store
                .get_secret_by_id(&expired_secret.id)
                .expect("expired secret lookup should succeed")
                .is_some()
        );
        assert!(
            restarted_store
                .get_secret_by_id(&active_secret.id)
                .expect("active secret lookup should succeed")
                .is_some()
        );
        assert!(
            restarted_store
                .consume_unexpired_secret_by_id(&active_secret.id, 500)
                .expect("active secret consumption should succeed")
                .is_some()
        );

        cleanup_temp_dir(&temp_root);
    }

    fn sample_secret(id: &str, created_at: i64, expires_at: i64) -> NewSecretRecord {
        let generated = generate_secret_reference();

        NewSecretRecord {
            id: id.to_owned(),
            ciphertext: format!("ciphertext-{id}"),
            nonce: format!("nonce-{id}"),
            created_at,
            expires_at,
            delete_token_hash: hash_delete_token(&generated.delete_token),
            size_bytes: 32,
            requester_ip_hash: None,
        }
    }

    fn setup_secret_store(prefix: &str) -> (PathBuf, SecretStore) {
        let temp_root = unique_temp_dir(prefix);
        let mut config = AppConfig::default();
        config.database_path = temp_root.join("secrets.db");
        let database = Database::bootstrap(&config).expect("database bootstrap should succeed");

        (temp_root, SecretStore::new(database))
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();

        std::env::temp_dir().join(format!("psst-rs-maintenance-{prefix}-{unique}"))
    }

    fn cleanup_temp_dir(path: &std::path::Path) {
        fs::remove_dir_all(path)
            .with_context(|| format!("failed to remove temporary directory {}", path.display()))
            .expect("temporary directory cleanup should succeed");
    }
}
