use std::{
    env,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
};

use anyhow::{Context, Result, bail};

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3000";
const DEFAULT_DATABASE_PATH: &str = "/var/lib/psst-rs/secrets.db";
const DEFAULT_PUBLIC_BASE_URL: &str = "https://example.tld";
const DEFAULT_MAX_SECRET_BYTES: u64 = 16 * 1024;
const DEFAULT_MAX_CIPHERTEXT_BYTES: u64 = 32 * 1024;
const DEFAULT_DEFAULT_TTL_SECONDS: u64 = 24 * 60 * 60;
const DEFAULT_MAX_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;
const DEFAULT_ENABLE_CREATE: bool = true;
const DEFAULT_GLOBAL_MAX_ACTIVE_SECRETS: u64 = 10_000;
const DEFAULT_GLOBAL_MAX_STORAGE_BYTES: u64 = 50 * 1024 * 1024;
const DEFAULT_CREATE_RATE_LIMIT_PER_MINUTE: u64 = 5;
const DEFAULT_CREATE_RATE_LIMIT_PER_HOUR: u64 = 30;
const DEFAULT_READ_RATE_LIMIT_PER_MINUTE: u64 = 60;
const DEFAULT_IP_HASH_SALT: &str = "";
const DEFAULT_TRUSTED_PROXY_IPS: &str = "127.0.0.1,::1";
const DEFAULT_TURNSTILE_VERIFY_URL: &str =
    "https://challenges.cloudflare.com/turnstile/v0/siteverify";

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub bind_addr: SocketAddr,
    pub database_path: PathBuf,
    pub public_base_url: String,
    pub max_secret_bytes: u64,
    pub max_ciphertext_bytes: u64,
    pub default_ttl_seconds: u64,
    pub max_ttl_seconds: u64,
    pub enable_create: bool,
    pub global_max_active_secrets: u64,
    pub global_max_storage_bytes: u64,
    pub create_rate_limit_per_minute: u64,
    pub create_rate_limit_per_hour: u64,
    pub read_rate_limit_per_minute: u64,
    pub ip_hash_salt: String,
    pub trusted_proxy_ips: Vec<IpAddr>,
    pub turnstile_site_key: String,
    pub turnstile_secret_key: String,
    pub turnstile_verify_url: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| env::var(key).ok())
    }

    fn from_lookup<F>(get_var: F) -> Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let config = Self {
            bind_addr: env_or_parse(&get_var, "SECRET_RS_BIND_ADDR", DEFAULT_BIND_ADDR)?,
            database_path: env_or_path(&get_var, "SECRET_RS_DATABASE_PATH", DEFAULT_DATABASE_PATH),
            public_base_url: env_or_string(
                &get_var,
                "SECRET_RS_PUBLIC_BASE_URL",
                DEFAULT_PUBLIC_BASE_URL,
            ),
            max_secret_bytes: env_or_parse(
                &get_var,
                "SECRET_RS_MAX_SECRET_BYTES",
                DEFAULT_MAX_SECRET_BYTES.to_string().as_str(),
            )?,
            max_ciphertext_bytes: env_or_parse(
                &get_var,
                "SECRET_RS_MAX_CIPHERTEXT_BYTES",
                DEFAULT_MAX_CIPHERTEXT_BYTES.to_string().as_str(),
            )?,
            default_ttl_seconds: env_or_parse(
                &get_var,
                "SECRET_RS_DEFAULT_TTL_SECONDS",
                DEFAULT_DEFAULT_TTL_SECONDS.to_string().as_str(),
            )?,
            max_ttl_seconds: env_or_parse(
                &get_var,
                "SECRET_RS_MAX_TTL_SECONDS",
                DEFAULT_MAX_TTL_SECONDS.to_string().as_str(),
            )?,
            enable_create: env_or_parse(
                &get_var,
                "SECRET_RS_ENABLE_CREATE",
                if DEFAULT_ENABLE_CREATE {
                    "true"
                } else {
                    "false"
                },
            )?,
            global_max_active_secrets: env_or_parse(
                &get_var,
                "SECRET_RS_GLOBAL_MAX_ACTIVE_SECRETS",
                DEFAULT_GLOBAL_MAX_ACTIVE_SECRETS.to_string().as_str(),
            )?,
            global_max_storage_bytes: env_or_parse(
                &get_var,
                "SECRET_RS_GLOBAL_MAX_STORAGE_BYTES",
                DEFAULT_GLOBAL_MAX_STORAGE_BYTES.to_string().as_str(),
            )?,
            create_rate_limit_per_minute: env_or_parse(
                &get_var,
                "SECRET_RS_CREATE_RATE_LIMIT_PER_MINUTE",
                DEFAULT_CREATE_RATE_LIMIT_PER_MINUTE.to_string().as_str(),
            )?,
            create_rate_limit_per_hour: env_or_parse(
                &get_var,
                "SECRET_RS_CREATE_RATE_LIMIT_PER_HOUR",
                DEFAULT_CREATE_RATE_LIMIT_PER_HOUR.to_string().as_str(),
            )?,
            read_rate_limit_per_minute: env_or_parse(
                &get_var,
                "SECRET_RS_READ_RATE_LIMIT_PER_MINUTE",
                DEFAULT_READ_RATE_LIMIT_PER_MINUTE.to_string().as_str(),
            )?,
            ip_hash_salt: env_or_string(&get_var, "SECRET_RS_IP_HASH_SALT", DEFAULT_IP_HASH_SALT),
            trusted_proxy_ips: env_or_ip_list(
                &get_var,
                "SECRET_RS_TRUSTED_PROXY_IPS",
                DEFAULT_TRUSTED_PROXY_IPS,
            )?,
            turnstile_site_key: env_or_string(&get_var, "SECRET_RS_TURNSTILE_SITE_KEY", ""),
            turnstile_secret_key: env_or_string(&get_var, "SECRET_RS_TURNSTILE_SECRET_KEY", ""),
            turnstile_verify_url: env_or_string(
                &get_var,
                "SECRET_RS_TURNSTILE_VERIFY_URL",
                DEFAULT_TURNSTILE_VERIFY_URL,
            ),
        };

        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if !self.bind_addr.ip().is_loopback() {
            bail!("SECRET_RS_BIND_ADDR must bind to a loopback address");
        }

        if self.database_path.as_os_str().is_empty() {
            bail!("SECRET_RS_DATABASE_PATH must not be empty");
        }

        if self.public_base_url.trim().is_empty() {
            bail!("SECRET_RS_PUBLIC_BASE_URL must not be empty");
        }

        if self.max_secret_bytes == 0 {
            bail!("SECRET_RS_MAX_SECRET_BYTES must be greater than zero");
        }

        if self.max_ciphertext_bytes < self.max_secret_bytes {
            bail!("SECRET_RS_MAX_CIPHERTEXT_BYTES must be >= SECRET_RS_MAX_SECRET_BYTES");
        }

        if self.default_ttl_seconds == 0 {
            bail!("SECRET_RS_DEFAULT_TTL_SECONDS must be greater than zero");
        }

        if self.max_ttl_seconds < self.default_ttl_seconds {
            bail!("SECRET_RS_MAX_TTL_SECONDS must be >= SECRET_RS_DEFAULT_TTL_SECONDS");
        }

        if self.global_max_active_secrets == 0 {
            bail!("SECRET_RS_GLOBAL_MAX_ACTIVE_SECRETS must be greater than zero");
        }

        if self.global_max_storage_bytes == 0 {
            bail!("SECRET_RS_GLOBAL_MAX_STORAGE_BYTES must be greater than zero");
        }

        if self.create_rate_limit_per_minute == 0 {
            bail!("SECRET_RS_CREATE_RATE_LIMIT_PER_MINUTE must be greater than zero");
        }

        if self.create_rate_limit_per_hour == 0 {
            bail!("SECRET_RS_CREATE_RATE_LIMIT_PER_HOUR must be greater than zero");
        }

        if self.read_rate_limit_per_minute == 0 {
            bail!("SECRET_RS_READ_RATE_LIMIT_PER_MINUTE must be greater than zero");
        }

        if self.ip_hash_salt.trim().is_empty() {
            bail!("SECRET_RS_IP_HASH_SALT must not be empty");
        }

        if self.trusted_proxy_ips.is_empty() {
            bail!("SECRET_RS_TRUSTED_PROXY_IPS must not be empty");
        }

        if self.enable_create && self.turnstile_site_key.trim().is_empty() {
            bail!("SECRET_RS_TURNSTILE_SITE_KEY must not be empty when creation is enabled");
        }

        if self.enable_create && self.turnstile_secret_key.trim().is_empty() {
            bail!("SECRET_RS_TURNSTILE_SECRET_KEY must not be empty when creation is enabled");
        }

        if self.enable_create && self.turnstile_verify_url.trim().is_empty() {
            bail!("SECRET_RS_TURNSTILE_VERIFY_URL must not be empty when creation is enabled");
        }

        Ok(())
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            bind_addr: DEFAULT_BIND_ADDR
                .parse()
                .expect("default bind addr should parse"),
            database_path: PathBuf::from(DEFAULT_DATABASE_PATH),
            public_base_url: DEFAULT_PUBLIC_BASE_URL.to_owned(),
            max_secret_bytes: DEFAULT_MAX_SECRET_BYTES,
            max_ciphertext_bytes: DEFAULT_MAX_CIPHERTEXT_BYTES,
            default_ttl_seconds: DEFAULT_DEFAULT_TTL_SECONDS,
            max_ttl_seconds: DEFAULT_MAX_TTL_SECONDS,
            enable_create: DEFAULT_ENABLE_CREATE,
            global_max_active_secrets: DEFAULT_GLOBAL_MAX_ACTIVE_SECRETS,
            global_max_storage_bytes: DEFAULT_GLOBAL_MAX_STORAGE_BYTES,
            create_rate_limit_per_minute: DEFAULT_CREATE_RATE_LIMIT_PER_MINUTE,
            create_rate_limit_per_hour: DEFAULT_CREATE_RATE_LIMIT_PER_HOUR,
            read_rate_limit_per_minute: DEFAULT_READ_RATE_LIMIT_PER_MINUTE,
            ip_hash_salt: "test-ip-hash-salt".to_owned(),
            trusted_proxy_ips: vec![
                "127.0.0.1"
                    .parse()
                    .expect("default trusted proxy ip should parse"),
                "::1"
                    .parse()
                    .expect("default trusted proxy ip should parse"),
            ],
            turnstile_site_key: "test-turnstile-site-key".to_owned(),
            turnstile_secret_key: "test-turnstile-secret-key".to_owned(),
            turnstile_verify_url: DEFAULT_TURNSTILE_VERIFY_URL.to_owned(),
        }
    }
}

fn env_or_string<F>(get_var: &F, key: &str, default: &str) -> String
where
    F: Fn(&str) -> Option<String>,
{
    get_var(key).unwrap_or_else(|| default.to_owned())
}

fn env_or_path<F>(get_var: &F, key: &str, default: &str) -> PathBuf
where
    F: Fn(&str) -> Option<String>,
{
    PathBuf::from(env_or_string(get_var, key, default))
}

fn env_or_parse<F, T>(get_var: &F, key: &str, default: &str) -> Result<T>
where
    F: Fn(&str) -> Option<String>,
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let raw = env_or_string(get_var, key, default);
    raw.parse::<T>()
        .with_context(|| format!("invalid value for {key}: {raw}"))
}

fn env_or_ip_list<F>(get_var: &F, key: &str, default: &str) -> Result<Vec<IpAddr>>
where
    F: Fn(&str) -> Option<String>,
{
    let raw = env_or_string(get_var, key, default);
    let mut ips = Vec::new();

    for value in raw.split(',') {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }

        ips.push(
            value
                .parse::<IpAddr>()
                .with_context(|| format!("invalid IP address in {key}: {value}"))?,
        );
    }

    Ok(ips)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::AppConfig;

    #[test]
    fn loads_default_configuration() {
        let config = AppConfig::from_lookup(|key| match key {
            "SECRET_RS_IP_HASH_SALT" => Some("test-ip-hash-salt".to_owned()),
            "SECRET_RS_TURNSTILE_SITE_KEY" => Some("site-key".to_owned()),
            "SECRET_RS_TURNSTILE_SECRET_KEY" => Some("secret-key".to_owned()),
            _ => None,
        })
        .expect("default config should load");

        assert_eq!(config.bind_addr.to_string(), "127.0.0.1:3000");
        assert_eq!(config.max_secret_bytes, 16 * 1024);
        assert!(config.enable_create);
        assert_eq!(config.global_max_active_secrets, 10_000);
        assert_eq!(config.global_max_storage_bytes, 50 * 1024 * 1024);
        assert_eq!(config.create_rate_limit_per_minute, 5);
        assert_eq!(config.create_rate_limit_per_hour, 30);
        assert_eq!(config.read_rate_limit_per_minute, 60);
        assert_eq!(config.ip_hash_salt, "test-ip-hash-salt");
        assert_eq!(config.trusted_proxy_ips.len(), 2);
        assert_eq!(config.turnstile_site_key, "site-key");
        assert_eq!(config.turnstile_secret_key, "secret-key");
    }

    #[test]
    fn loads_configured_rate_limits() {
        let config = AppConfig::from_lookup(|key| match key {
            "SECRET_RS_IP_HASH_SALT" => Some("test-ip-hash-salt".to_owned()),
            "SECRET_RS_TURNSTILE_SITE_KEY" => Some("site-key".to_owned()),
            "SECRET_RS_TURNSTILE_SECRET_KEY" => Some("secret-key".to_owned()),
            "SECRET_RS_CREATE_RATE_LIMIT_PER_MINUTE" => Some("7".to_owned()),
            "SECRET_RS_CREATE_RATE_LIMIT_PER_HOUR" => Some("42".to_owned()),
            "SECRET_RS_READ_RATE_LIMIT_PER_MINUTE" => Some("90".to_owned()),
            _ => None,
        })
        .expect("config should load");

        assert_eq!(config.create_rate_limit_per_minute, 7);
        assert_eq!(config.create_rate_limit_per_hour, 42);
        assert_eq!(config.read_rate_limit_per_minute, 90);
    }

    #[test]
    fn rejects_missing_turnstile_keys_when_creation_is_enabled() {
        let error = AppConfig::from_lookup(|key| match key {
            "SECRET_RS_IP_HASH_SALT" => Some("test-ip-hash-salt".to_owned()),
            _ => None,
        })
        .expect_err("config should be rejected");

        assert!(
            error
                .to_string()
                .contains("SECRET_RS_TURNSTILE_SITE_KEY must not be empty")
        );
    }

    #[test]
    fn rejects_missing_ip_hash_salt() {
        let mut config = AppConfig::default();
        config.ip_hash_salt.clear();

        let error = config.validate().expect_err("config should be rejected");

        assert!(
            error
                .to_string()
                .contains("SECRET_RS_IP_HASH_SALT must not be empty")
        );
    }

    #[test]
    fn rejects_non_loopback_bind_address() {
        let mut config = AppConfig::default();
        config.bind_addr = SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 3000));

        let error = config.validate().expect_err("config should be rejected");

        assert!(
            error
                .to_string()
                .contains("SECRET_RS_BIND_ADDR must bind to a loopback address")
        );
    }

    #[test]
    fn rejects_empty_trusted_proxy_list() {
        let mut config = AppConfig::default();
        config.trusted_proxy_ips.clear();

        let error = config.validate().expect_err("config should be rejected");

        assert!(
            error
                .to_string()
                .contains("SECRET_RS_TRUSTED_PROXY_IPS must not be empty")
        );
    }

    #[test]
    fn rejects_zero_global_secret_quota() {
        let mut config = AppConfig::default();
        config.global_max_active_secrets = 0;

        let error = config.validate().expect_err("config should be rejected");

        assert!(
            error
                .to_string()
                .contains("SECRET_RS_GLOBAL_MAX_ACTIVE_SECRETS must be greater than zero")
        );
    }

    #[test]
    fn rejects_zero_create_rate_limit_per_minute() {
        let mut config = AppConfig::default();
        config.create_rate_limit_per_minute = 0;

        let error = config.validate().expect_err("config should be rejected");

        assert!(
            error
                .to_string()
                .contains("SECRET_RS_CREATE_RATE_LIMIT_PER_MINUTE must be greater than zero")
        );
    }

    #[test]
    fn rejects_zero_create_rate_limit_per_hour() {
        let mut config = AppConfig::default();
        config.create_rate_limit_per_hour = 0;

        let error = config.validate().expect_err("config should be rejected");

        assert!(
            error
                .to_string()
                .contains("SECRET_RS_CREATE_RATE_LIMIT_PER_HOUR must be greater than zero")
        );
    }

    #[test]
    fn rejects_zero_read_rate_limit_per_minute() {
        let mut config = AppConfig::default();
        config.read_rate_limit_per_minute = 0;

        let error = config.validate().expect_err("config should be rejected");

        assert!(
            error
                .to_string()
                .contains("SECRET_RS_READ_RATE_LIMIT_PER_MINUTE must be greater than zero")
        );
    }
}
