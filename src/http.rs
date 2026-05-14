use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, MatchedPath, Request, State},
    http::{
        HeaderValue, Response, StatusCode,
        header::{CONTENT_SECURITY_POLICY, HeaderName, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS},
    },
    middleware::{self, Next},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use tracing::info;

use crate::{
    config::AppConfig,
    db::{Database, NewSecretRecord, SecretStore},
    request_context::ClientIp,
    secret::{
        CreateSecretRequest, CreateSecretResponse, generate_secret_reference, is_allowed_ttl,
    },
};

static HEADER_PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");

const HTML_CSP: &str = concat!(
    "default-src 'self'; ",
    "script-src 'self' https://challenges.cloudflare.com; ",
    "frame-src https://challenges.cloudflare.com; ",
    "style-src 'self'; ",
    "img-src 'self'; ",
    "connect-src 'self'; ",
    "base-uri 'none'; ",
    "form-action 'self'; ",
    "frame-ancestors 'none'"
);

#[derive(Clone)]
struct AppState {
    config: AppConfig,
    secret_store: SecretStore,
}

#[derive(Debug, serde::Serialize)]
struct ErrorResponse {
    error: String,
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn service_unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response<Body> {
        let body = Json(ErrorResponse {
            error: self.message,
        });

        (self.status, body).into_response()
    }
}

pub fn build_router(config: AppConfig, database: Database) -> Router {
    let max_json_body_bytes =
        usize::try_from(config.max_ciphertext_bytes.saturating_add(4096)).unwrap_or(usize::MAX);
    let app_state = AppState {
        config: config.clone(),
        secret_store: SecretStore::new(database),
    };

    Router::new()
        .route("/", get(index))
        .route("/about", get(about))
        .route("/healthz", get(healthz))
        .route("/api/create", post(create_secret_stub))
        .with_state(app_state)
        .layer(DefaultBodyLimit::max(max_json_body_bytes))
        .layer(middleware::from_fn(log_request))
        .layer(middleware::from_fn_with_state(config, extract_client_ip))
        .layer(middleware::from_fn(apply_security_headers))
}

async fn index() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html lang="fr">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>secret-rs</title>
  </head>
  <body>
    <main>
      <h1>secret-rs</h1>
      <p>Service minimaliste de partage de secrets a lecture unique.</p>
    </main>
  </body>
</html>"#,
    )
}

async fn about() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html lang="fr">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>A propos</title>
  </head>
  <body>
    <main>
      <h1>A propos</h1>
      <p>Les secrets seront chiffres dans le navigateur et lus une seule fois.</p>
    </main>
  </body>
</html>"#,
    )
}

async fn healthz() -> &'static str {
    "ok"
}

async fn create_secret_stub(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(payload): Json<CreateSecretRequest>,
) -> Result<Json<CreateSecretResponse>, ApiError> {
    if !state.config.enable_create {
        return Err(ApiError::service_unavailable(
            "secret creation is temporarily disabled",
        ));
    }

    validate_create_request(&state.config, &payload)?;

    let generated = generate_secret_reference();
    let now_timestamp = current_timestamp()?;
    let ciphertext_size_bytes = u64::try_from(payload.ciphertext.len())
        .map_err(|_| ApiError::internal("ciphertext length overflow"))?;
    let expires_at = now_timestamp
        .checked_add(
            i64::try_from(payload.expires_in_seconds)
                .map_err(|_| ApiError::bad_request("expires_in_seconds is too large"))?,
        )
        .ok_or_else(|| ApiError::bad_request("expires_in_seconds is too large"))?;

    let new_secret = NewSecretRecord {
        id: generated.secret_id.clone(),
        ciphertext: payload.ciphertext,
        nonce: payload.nonce,
        created_at: now_timestamp,
        expires_at,
        delete_token_hash: generated.delete_token_hash,
        size_bytes: ciphertext_size_bytes,
        requester_ip_hash: None,
    };

    state
        .secret_store
        .insert_secret(&new_secret)
        .map_err(|error| ApiError::internal(format!("failed to persist secret: {error}")))?;

    Ok(Json(CreateSecretResponse {
        id: generated.secret_id,
        delete_token: generated.delete_token,
    }))
}

async fn apply_security_headers(request: Request, next: Next) -> Response<Body> {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(HTML_CSP),
    );
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        HEADER_PERMISSIONS_POLICY.clone(),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );

    response
}

async fn extract_client_ip(
    State(config): State<AppConfig>,
    mut request: Request,
    next: Next,
) -> Response<Body> {
    if let Some(ConnectInfo(peer_addr)) = request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
    {
        let client_ip =
            ClientIp::from_request(peer_addr.ip(), request.headers(), &config.trusted_proxy_ips);
        request.extensions_mut().insert(client_ip);
    }

    next.run(request).await
}

async fn log_request(request: Request, next: Next) -> Response<Body> {
    let method = request.method().clone();
    let path = matched_path_or_uri(&request).to_owned();
    let has_client_ip = request.extensions().get::<ClientIp>().is_some();
    let started_at = Instant::now();

    let response = next.run(request).await;
    let status = response.status();
    let elapsed_ms = started_at.elapsed().as_millis();

    info!(
        method = %method,
        path,
        status = status.as_u16(),
        latency_ms = elapsed_ms,
        has_client_ip,
        "request completed"
    );

    response
}

fn matched_path_or_uri(request: &Request) -> &str {
    request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("unmatched")
}

fn validate_create_request(config: &AppConfig, payload: &CreateSecretRequest) -> Result<(), ApiError> {
    if payload.ciphertext.is_empty() {
        return Err(ApiError::bad_request("ciphertext must not be empty"));
    }

    if u64::try_from(payload.ciphertext.len())
        .map_err(|_| ApiError::bad_request("ciphertext is too large"))?
        > config.max_ciphertext_bytes
    {
        return Err(ApiError::bad_request("ciphertext exceeds the configured size limit"));
    }

    if payload.nonce.is_empty() {
        return Err(ApiError::bad_request("nonce must not be empty"));
    }

    if u64::try_from(payload.nonce.len())
        .map_err(|_| ApiError::bad_request("nonce is too large"))?
        > config.max_ciphertext_bytes
    {
        return Err(ApiError::bad_request("nonce exceeds the configured size limit"));
    }

    if payload.turnstile_token.is_empty() {
        return Err(ApiError::bad_request("turnstile_token must not be empty"));
    }

    if !is_allowed_ttl(payload.expires_in_seconds) {
        return Err(ApiError::bad_request("expires_in_seconds is not an allowed TTL"));
    }

    if payload.expires_in_seconds > config.max_ttl_seconds {
        return Err(ApiError::bad_request("expires_in_seconds exceeds the configured TTL limit"));
    }

    Ok(())
}

fn current_timestamp() -> Result<i64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::internal("system clock is before the Unix epoch"))
        .and_then(|duration| {
            i64::try_from(duration.as_secs())
                .map_err(|_| ApiError::internal("current timestamp exceeds supported range"))
        })
}

#[cfg(test)]
mod tests {
    use std::{
        time::{SystemTime, UNIX_EPOCH},
    };

    use axum::{
        body::Body,
        http::{Method, Request, StatusCode, header},
    };
    use serde_json::Value;
    use tower::util::ServiceExt;

    use super::{build_router, matched_path_or_uri};
    use crate::{config::AppConfig, db::Database, secret::hash_delete_token};

    #[tokio::test]
    async fn html_routes_include_security_headers() {
        let (_guard, app, _database) = test_router("html-headers", AppConfig::default());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_SECURITY_POLICY),
            Some(&header_value(
                "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
            ))
        );
        assert_eq!(
            response.headers().get(header::REFERRER_POLICY),
            Some(&header_value("no-referrer"))
        );
        assert_eq!(
            response.headers().get(header::X_FRAME_OPTIONS),
            Some(&header_value("DENY"))
        );
    }

    #[tokio::test]
    async fn unsupported_method_returns_405() {
        let (_guard, app, _database) = test_router("method-405", AppConfig::default());

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/healthz")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn create_route_rejects_oversized_json_bodies() {
        let (_guard, app, _database) = test_router("oversized-json", AppConfig::default());
        let oversized_body = format!(r#"{{"ciphertext":"{}","nonce":"n","expires_in_seconds":1,"turnstile_token":"t"}}"#, "a".repeat(40_000));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/create")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(oversized_body))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn create_route_persists_secret_and_returns_reference() {
        let (_guard, app, database) = test_router("create-success", AppConfig::default());

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/create")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"ciphertext":"ciphertext-value","nonce":"nonce-value","expires_in_seconds":86400,"turnstile_token":"dummy-token"}"#,
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let json: Value = serde_json::from_slice(&body).expect("body should be JSON");

        let secret_id = json
            .get("id")
            .and_then(Value::as_str)
            .expect("id should be present");
        let delete_token = json
            .get("delete_token")
            .and_then(Value::as_str)
            .expect("delete_token should be present");

        let connection = database
            .open_connection()
            .expect("database connection should open");
        let stored = connection
            .query_row(
                "SELECT ciphertext, nonce, delete_token_hash FROM secrets WHERE id = ?1",
                [secret_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .expect("secret should be stored");

        assert_eq!(stored.0, "ciphertext-value");
        assert_eq!(stored.1, "nonce-value");
        assert_eq!(stored.2, hash_delete_token(delete_token));
    }

    #[tokio::test]
    async fn create_route_rejects_invalid_ttl() {
        let (_guard, app, _database) = test_router("invalid-ttl", AppConfig::default());

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/create")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"ciphertext":"ciphertext-value","nonce":"nonce-value","expires_in_seconds":42,"turnstile_token":"dummy-token"}"#,
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_route_returns_503_when_creation_is_disabled() {
        let mut config = AppConfig::default();
        config.enable_create = false;
        let (_guard, app, _database) = test_router("create-disabled", config);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/create")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"ciphertext":"ciphertext-value","nonce":"nonce-value","expires_in_seconds":86400,"turnstile_token":"dummy-token"}"#,
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn unmatched_requests_do_not_log_raw_uri_paths() {
        let request = Request::builder()
            .uri("/s/some-secret-id")
            .body(Body::empty())
            .expect("request should build");

        assert_eq!(matched_path_or_uri(&request), "unmatched");
    }

    fn header_value(value: &'static str) -> header::HeaderValue {
        header::HeaderValue::from_static(value)
    }

    fn test_router(prefix: &str, mut config: AppConfig) -> (TestTempDirGuard, axum::Router, Database) {
        let temp_root = unique_temp_dir(prefix);
        config.database_path = temp_root.join("secrets.db");

        let database = Database::bootstrap(&config).expect("database bootstrap should succeed");
        let router = build_router(config, database.clone());

        (TestTempDirGuard(temp_root), router, database)
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();

        std::env::temp_dir().join(format!("secret-rs-http-{prefix}-{unique}"))
    }

    impl Drop for TestTempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct TestTempDirGuard(std::path::PathBuf);
}
