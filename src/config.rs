use std::{env, net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::{Context, Result, bail};

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3000";
const DEFAULT_DATABASE_PATH: &str = "/var/lib/secret-rs/secrets.db";
const DEFAULT_PUBLIC_BASE_URL: &str = "https://example.tld";
const DEFAULT_MAX_SECRET_BYTES: u64 = 16 * 1024;
const DEFAULT_MAX_CIPHERTEXT_BYTES: u64 = 32 * 1024;
const DEFAULT_DEFAULT_TTL_SECONDS: u64 = 24 * 60 * 60;
const DEFAULT_MAX_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;
const DEFAULT_ENABLE_CREATE: bool = true;

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

        Ok(())
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

#[cfg(test)]
mod tests {
    use super::AppConfig;

    #[test]
    fn loads_default_configuration() {
        let config = AppConfig::from_env().expect("default config should load");

        assert_eq!(config.bind_addr.to_string(), "127.0.0.1:3000");
        assert_eq!(config.max_secret_bytes, 16 * 1024);
        assert!(config.enable_create);
    }
}
