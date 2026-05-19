use std::{
    fmt::Write as _,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
};

use crate::config::AppConfig;

const R: Ordering = Ordering::Relaxed;

#[derive(Default)]
pub struct AppMetrics {
    pub secrets_created: AtomicU64,
    pub secrets_read: AtomicU64,
    pub secrets_expired: AtomicU64,
    pub secrets_deleted: AtomicU64,
    pub abuse_reports: AtomicU64,
    pub create_rejected_too_large: AtomicU64,
    pub create_rejected_invalid_ttl: AtomicU64,
    pub create_rejected_turnstile_failed: AtomicU64,
    pub create_rejected_rate_limited: AtomicU64,
    pub create_rejected_storage_limit: AtomicU64,
    pub create_rejected_invalid_payload: AtomicU64,
    pub rate_limited_create: AtomicU64,
    pub rate_limited_read: AtomicU64,
    pub rate_limited_report: AtomicU64,
    pub db_errors_create: AtomicU64,
    pub db_errors_read: AtomicU64,
    pub db_errors_delete: AtomicU64,
    pub db_errors_purge: AtomicU64,
    pub db_errors_metrics: AtomicU64,
    pub purge_runs: AtomicU64,
    pub purge_deleted: AtomicU64,
    pub active_secrets: AtomicI64,
    pub storage_bytes: AtomicI64,
}

impl AppMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn render(&self, config: &AppConfig) -> String {
        let mut buf = String::with_capacity(4096);

        let version = env!("CARGO_PKG_VERSION");
        let commit = option_env!("PSST_RS_BUILD_COMMIT").unwrap_or("unknown");
        let _ = writeln!(buf, "# HELP psst_build_info Build information.");
        let _ = writeln!(buf, "# TYPE psst_build_info gauge");
        let _ = writeln!(
            buf,
            "psst_build_info{{version=\"{version}\",commit=\"{commit}\"}} 1"
        );

        write_counter(&mut buf, "psst_secrets_created_total", "Total secrets created.", self.secrets_created.load(R));
        write_counter(&mut buf, "psst_secrets_read_total", "Total secrets read.", self.secrets_read.load(R));
        write_counter(&mut buf, "psst_secrets_expired_total", "Total secrets deleted by expiry maintenance.", self.secrets_expired.load(R));
        write_counter(&mut buf, "psst_secrets_deleted_total", "Total secrets deleted by owner.", self.secrets_deleted.load(R));
        write_counter(&mut buf, "psst_abuse_reports_total", "Total abuse reports submitted.", self.abuse_reports.load(R));

        let _ = writeln!(buf, "# HELP psst_create_rejected_total Total create requests rejected by reason.");
        let _ = writeln!(buf, "# TYPE psst_create_rejected_total counter");
        let _ = writeln!(buf, "psst_create_rejected_total{{reason=\"too_large\"}} {}", self.create_rejected_too_large.load(R));
        let _ = writeln!(buf, "psst_create_rejected_total{{reason=\"invalid_ttl\"}} {}", self.create_rejected_invalid_ttl.load(R));
        let _ = writeln!(buf, "psst_create_rejected_total{{reason=\"turnstile_failed\"}} {}", self.create_rejected_turnstile_failed.load(R));
        let _ = writeln!(buf, "psst_create_rejected_total{{reason=\"rate_limited\"}} {}", self.create_rejected_rate_limited.load(R));
        let _ = writeln!(buf, "psst_create_rejected_total{{reason=\"storage_limit\"}} {}", self.create_rejected_storage_limit.load(R));
        let _ = writeln!(buf, "psst_create_rejected_total{{reason=\"invalid_payload\"}} {}", self.create_rejected_invalid_payload.load(R));

        let _ = writeln!(buf, "# HELP psst_rate_limited_total Total requests rejected by rate limiter.");
        let _ = writeln!(buf, "# TYPE psst_rate_limited_total counter");
        let _ = writeln!(buf, "psst_rate_limited_total{{operation=\"create\"}} {}", self.rate_limited_create.load(R));
        let _ = writeln!(buf, "psst_rate_limited_total{{operation=\"read\"}} {}", self.rate_limited_read.load(R));
        let _ = writeln!(buf, "psst_rate_limited_total{{operation=\"report\"}} {}", self.rate_limited_report.load(R));

        let _ = writeln!(buf, "# HELP psst_db_errors_total Total database errors by operation.");
        let _ = writeln!(buf, "# TYPE psst_db_errors_total counter");
        let _ = writeln!(buf, "psst_db_errors_total{{operation=\"create\"}} {}", self.db_errors_create.load(R));
        let _ = writeln!(buf, "psst_db_errors_total{{operation=\"read\"}} {}", self.db_errors_read.load(R));
        let _ = writeln!(buf, "psst_db_errors_total{{operation=\"delete\"}} {}", self.db_errors_delete.load(R));
        let _ = writeln!(buf, "psst_db_errors_total{{operation=\"purge\"}} {}", self.db_errors_purge.load(R));
        let _ = writeln!(buf, "psst_db_errors_total{{operation=\"metrics\"}} {}", self.db_errors_metrics.load(R));

        write_counter(&mut buf, "psst_purge_runs_total", "Total maintenance purge runs.", self.purge_runs.load(R));
        write_counter(&mut buf, "psst_purge_deleted_total", "Total expired secrets deleted by purge runs.", self.purge_deleted.load(R));

        write_gauge_i64(&mut buf, "psst_active_secrets", "Number of currently active (unexpired, unconsumed) secrets.", self.active_secrets.load(R));
        write_gauge_i64(&mut buf, "psst_storage_bytes", "Total storage bytes used by active secrets.", self.storage_bytes.load(R));

        write_gauge(&mut buf, "psst_config_max_secret_bytes", "Configured maximum secret size in bytes.", config.max_secret_bytes);
        write_gauge(&mut buf, "psst_config_max_ttl_seconds", "Configured maximum TTL in seconds.", config.max_ttl_seconds);
        write_gauge(&mut buf, "psst_config_create_enabled", "Whether secret creation is enabled (1=yes, 0=no).", u64::from(config.enable_create));

        buf
    }
}

fn write_counter(buf: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(buf, "# HELP {name} {help}");
    let _ = writeln!(buf, "# TYPE {name} counter");
    let _ = writeln!(buf, "{name} {value}");
}

fn write_gauge(buf: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(buf, "# HELP {name} {help}");
    let _ = writeln!(buf, "# TYPE {name} gauge");
    let _ = writeln!(buf, "{name} {value}");
}

fn write_gauge_i64(buf: &mut String, name: &str, help: &str, value: i64) {
    let _ = writeln!(buf, "# HELP {name} {help}");
    let _ = writeln!(buf, "# TYPE {name} gauge");
    let _ = writeln!(buf, "{name} {}", value.max(0));
}
