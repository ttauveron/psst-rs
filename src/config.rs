use std::{
    env,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
};

use anyhow::{Context, Result, bail};

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3000";
const DEFAULT_DATABASE_PATH: &str = "/var/lib/secret-rs/secrets.db";
const DEFAULT_PUBLIC_BASE_URL: &str = "https://example.tld";
const DEFAULT_MAX_SECRET_BYTES: u64 = 16 * 1024;
const DEFAULT_MAX_CIPHERTEXT_BYTES: u64 = 32 * 1024;
const DEFAULT_DEFAULT_TTL_SECONDS: u64 = 24 * 60 * 60;
const DEFAULT_MAX_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;
const DEFAULT_ENABLE_CREATE: bool = true;
const DEFAULT_GLOBAL_MAX_ACTIVE_SECRETS: u64 = 10_000;
const DEFAULT_GLOBAL_MAX_STORAGE_BYTES: u64 = 50 * 1024 * 1024;
const DEFAULT_TRUSTED_PROXY_IPS: &str = "127.0.0.1,::1";

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
    pub trusted_proxy_ips: Vec<IpAddr>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        let config = Self {
            bind_addr: env_or_parse("SECRET_RS_BIND_ADDR", DEFAULT_BIND_ADDR)?,
            database_path: env_or_path("SECRET_RS_DATABASE_PATH", DEFAULT_DATABASE_PATH),
            public_base_url: env_or_string("SECRET_RS_PUBLIC_BASE_URL", DEFAULT_PUBLIC_BASE_URL),
            max_secret_bytes: env_or_parse(
                "SECRET_RS_MAX_SECRET_BYTES",
                DEFAULT_MAX_SECRET_BYTES.to_string().as_str(),
            )?,
            max_ciphertext_bytes: env_or_parse(
                "SECRET_RS_MAX_CIPHERTEXT_BYTES",
                DEFAULT_MAX_CIPHERTEXT_BYTES.to_string().as_str(),
            )?,
            default_ttl_seconds: env_or_parse(
                "SECRET_RS_DEFAULT_TTL_SECONDS",
                DEFAULT_DEFAULT_TTL_SECONDS.to_string().as_str(),
            )?,
            max_ttl_seconds: env_or_parse(
                "SECRET_RS_MAX_TTL_SECONDS",
                DEFAULT_MAX_TTL_SECONDS.to_string().as_str(),
            )?,
            enable_create: env_or_parse(
                "SECRET_RS_ENABLE_CREATE",
                if DEFAULT_ENABLE_CREATE { "true" } else { "false" },
            )?,
            global_max_active_secrets: env_or_parse(
                "SECRET_RS_GLOBAL_MAX_ACTIVE_SECRETS",
                DEFAULT_GLOBAL_MAX_ACTIVE_SECRETS.to_string().as_str(),
            )?,
            global_max_storage_bytes: env_or_parse(
                "SECRET_RS_GLOBAL_MAX_STORAGE_BYTES",
                DEFAULT_GLOBAL_MAX_STORAGE_BYTES.to_string().as_str(),
            )?,
            trusted_proxy_ips: env_or_ip_list(
                "SECRET_RS_TRUSTED_PROXY_IPS",
                DEFAULT_TRUSTED_PROXY_IPS,
            )?,
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

        if self.trusted_proxy_ips.is_empty() {
            bail!("SECRET_RS_TRUSTED_PROXY_IPS must not be empty");
        }

        Ok(())
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            bind_addr: DEFAULT_BIND_ADDR.parse().expect("default bind addr should parse"),
            database_path: PathBuf::from(DEFAULT_DATABASE_PATH),
            public_base_url: DEFAULT_PUBLIC_BASE_URL.to_owned(),
            max_secret_bytes: DEFAULT_MAX_SECRET_BYTES,
            max_ciphertext_bytes: DEFAULT_MAX_CIPHERTEXT_BYTES,
            default_ttl_seconds: DEFAULT_DEFAULT_TTL_SECONDS,
            max_ttl_seconds: DEFAULT_MAX_TTL_SECONDS,
            enable_create: DEFAULT_ENABLE_CREATE,
            global_max_active_secrets: DEFAULT_GLOBAL_MAX_ACTIVE_SECRETS,
            global_max_storage_bytes: DEFAULT_GLOBAL_MAX_STORAGE_BYTES,
            trusted_proxy_ips: vec![
                "127.0.0.1"
                    .parse()
                    .expect("default trusted proxy ip should parse"),
                "::1"
                    .parse()
                    .expect("default trusted proxy ip should parse"),
            ],
        }
    }
}

fn env_or_string(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn env_or_path(key: &str, default: &str) -> PathBuf {
    PathBuf::from(env_or_string(key, default))
}

fn env_or_parse<T>(key: &str, default: &str) -> Result<T>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let raw = env_or_string(key, default);
    raw.parse::<T>()
        .with_context(|| format!("invalid value for {key}: {raw}"))
}

fn env_or_ip_list(key: &str, default: &str) -> Result<Vec<IpAddr>> {
    let raw = env_or_string(key, default);
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
        let config = AppConfig::from_env().expect("default config should load");

        assert_eq!(config.bind_addr.to_string(), "127.0.0.1:3000");
        assert_eq!(config.max_secret_bytes, 16 * 1024);
        assert!(config.enable_create);
        assert_eq!(config.global_max_active_secrets, 10_000);
        assert_eq!(config.global_max_storage_bytes, 50 * 1024 * 1024);
        assert_eq!(config.trusted_proxy_ips.len(), 2);
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
}
