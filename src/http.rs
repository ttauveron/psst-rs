use std::{
    fmt::Write as _,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Extension, MatchedPath, Path, Request, State},
    http::{
        HeaderValue, Response, StatusCode,
        header::{
            self, CONTENT_SECURITY_POLICY, HeaderName, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
            X_FRAME_OPTIONS,
        },
    },
    middleware::{self, Next},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request as HyperRequest;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::{
    config::AppConfig,
    db::{ActiveSecretStats, Database, NewSecretRecord, SecretStore},
    rate_limit::RateLimitBucket,
    request_context::ClientIp,
    secret::{
        ALLOWED_TTL_SECONDS, CreateSecretRequest, CreateSecretResponse, DeleteSecretRequest,
        DeleteSecretResponse, ReadSecretResponse, generate_secret_reference, hash_delete_token,
        is_allowed_ttl,
    },
};

static HEADER_PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");
type TurnstileHttpClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;
const APP_CSS: &str = include_str!("../static/app.css");
const APP_JS: &str = include_str!("../static/app.js");
const RATE_LIMIT_EXCEEDED_MESSAGE: &str = "rate limit exceeded";

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
    turnstile_client: TurnstileHttpClient,
}

#[derive(Debug, serde::Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug)]
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

    fn too_many_requests() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: RATE_LIMIT_EXCEEDED_MESSAGE.to_owned(),
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
        turnstile_client: build_turnstile_client(),
    };

    Router::new()
        .route("/", get(index))
        .route("/s/{id}", get(read_secret_page))
        .route("/healthz", get(healthz))
        .route("/static/app.css", get(static_app_css))
        .route("/static/app.js", get(static_app_js))
        .route("/api/create", post(create_secret_stub))
        .route("/api/delete/{id}", post(delete_secret))
        .route("/api/secrets/{id}", get(read_secret))
        .with_state(app_state)
        .layer(DefaultBodyLimit::max(max_json_body_bytes))
        .layer(middleware::from_fn(log_request))
        .layer(middleware::from_fn_with_state(config, extract_client_ip))
        .layer(middleware::from_fn(apply_security_headers))
}

async fn index(State(state): State<AppState>) -> Html<String> {
    Html(render_index_page(&state.config))
}

async fn read_secret_page(Path(secret_id): Path<String>) -> Html<String> {
    Html(render_read_page(&secret_id))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn static_app_css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], APP_CSS)
}

async fn static_app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        APP_JS,
    )
}

fn build_turnstile_client() -> TurnstileHttpClient {
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();

    Client::builder(TokioExecutor::new()).build(https)
}

async fn create_secret_stub(
    axum::extract::State(state): axum::extract::State<AppState>,
    client_ip: Option<Extension<ClientIp>>,
    Json(payload): Json<CreateSecretRequest>,
) -> Result<Json<CreateSecretResponse>, ApiError> {
    let now_timestamp = current_timestamp()?;
    let validated = validate_create_request(&state.config, &payload)?;
    let client_ip = client_ip.map(|Extension(client_ip)| client_ip);
    let requester_ip_hash = client_ip
        .as_ref()
        .map(|client_ip| client_ip.hashed_identifier(&state.config.ip_hash_salt));

    ensure_create_enabled(&state.config)?;
    enforce_global_create_quotas(&state, now_timestamp, validated.ciphertext_size_bytes)?;
    check_create_rate_limit_hook(&state, requester_ip_hash.as_deref(), now_timestamp)?;
    verify_turnstile(&state, client_ip.map(|client_ip| client_ip.0), &payload).await?;

    let generated = generate_secret_reference();
    let expires_at = now_timestamp
        .checked_add(
            i64::try_from(validated.expires_in_seconds)
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
        size_bytes: validated.ciphertext_size_bytes,
        requester_ip_hash,
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

async fn read_secret(
    axum::extract::State(state): axum::extract::State<AppState>,
    client_ip: Option<Extension<ClientIp>>,
    Path(secret_id): Path<String>,
) -> Result<Json<ReadSecretResponse>, ApiError> {
    let now_timestamp = current_timestamp()?;
    let requester_ip_hash = client_ip
        .map(|Extension(client_ip)| client_ip.hashed_identifier(&state.config.ip_hash_salt));
    check_read_rate_limit(&state, requester_ip_hash.as_deref(), now_timestamp)?;

    let secret = state
        .secret_store
        .consume_unexpired_secret_by_id(&secret_id, now_timestamp)
        .map_err(|error| ApiError::internal(format!("failed to load secret: {error}")))?;

    let Some(secret) = secret else {
        return Err(ApiError {
            status: StatusCode::NOT_FOUND,
            message: "secret not found".to_owned(),
        });
    };

    Ok(Json(ReadSecretResponse {
        ciphertext: secret.ciphertext,
        nonce: secret.nonce,
    }))
}

async fn delete_secret(
    axum::extract::State(state): axum::extract::State<AppState>,
    Path(secret_id): Path<String>,
    Json(payload): Json<DeleteSecretRequest>,
) -> Result<Json<DeleteSecretResponse>, ApiError> {
    if payload.delete_token.is_empty() {
        return Err(ApiError::bad_request("delete_token must not be empty"));
    }

    let deleted = state
        .secret_store
        .delete_secret_by_id_and_token_hash(&secret_id, &hash_delete_token(&payload.delete_token))
        .map_err(|error| ApiError::internal(format!("failed to delete secret: {error}")))?;

    if !deleted {
        return Err(ApiError {
            status: StatusCode::NOT_FOUND,
            message: "secret not found".to_owned(),
        });
    }

    Ok(Json(DeleteSecretResponse { deleted: true }))
}

fn render_index_page(config: &AppConfig) -> String {
    let mut ttl_options = String::new();
    let asset_version = asset_version();
    let app_css_url = format!("/static/app.css?v={asset_version}");
    let app_js_url = format!("/static/app.js?v={asset_version}");

    for ttl_seconds in ALLOWED_TTL_SECONDS {
        let selected = if ttl_seconds == config.default_ttl_seconds {
            " selected"
        } else {
            ""
        };

        let _ = write!(
            ttl_options,
            r#"<option value="{ttl_seconds}"{selected}>{}</option>"#,
            ttl_label(ttl_seconds)
        );
    }

    render_template(
        include_str!("../templates/create.html"),
        &[
            ("{{APP_CSS_URL}}", &app_css_url),
            ("{{APP_JS_URL}}", &app_js_url),
            (
                "{{PUBLIC_BASE_URL}}",
                &escape_html_attribute(&config.public_base_url),
            ),
            ("{{MAX_SECRET_BYTES}}", &config.max_secret_bytes.to_string()),
            (
                "{{ENABLE_CREATE}}",
                if config.enable_create {
                    "true"
                } else {
                    "false"
                },
            ),
            (
                "{{TURNSTILE_SITE_KEY}}",
                &escape_html_attribute(&config.turnstile_site_key),
            ),
            ("{{TTL_OPTIONS}}", &ttl_options),
        ],
    )
}

fn render_read_page(secret_id: &str) -> String {
    let asset_version = asset_version();
    let app_css_url = format!("/static/app.css?v={asset_version}");
    let app_js_url = format!("/static/app.js?v={asset_version}");

    render_template(
        include_str!("../templates/read.html"),
        &[
            ("{{APP_CSS_URL}}", &app_css_url),
            ("{{APP_JS_URL}}", &app_js_url),
            ("{{SECRET_ID}}", &escape_html_attribute(secret_id)),
        ],
    )
}

fn asset_version() -> String {
    let mut digest = Sha256::new();
    digest.update(APP_CSS.as_bytes());
    digest.update(APP_JS.as_bytes());
    let hash = digest.finalize();

    hash[..6].iter().map(|byte| format!("{byte:02x}")).collect()
}

fn ttl_label(ttl_seconds: u64) -> &'static str {
    match ttl_seconds {
        ttl if ttl == 15 * 60 => "15 minutes",
        ttl if ttl == 60 * 60 => "1 hour",
        ttl if ttl == 24 * 60 * 60 => "24 hours",
        ttl if ttl == 7 * 24 * 60 * 60 => "7 days",
        _ => "Unsupported TTL",
    }
}

fn escape_html_attribute(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());

    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '"' => escaped.push_str("&quot;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }

    escaped
}

fn render_template(template: &str, replacements: &[(&str, &str)]) -> String {
    let mut rendered = template.to_owned();

    for (placeholder, value) in replacements {
        rendered = rendered.replace(placeholder, value);
    }

    rendered
}

async fn apply_security_headers(request: Request, next: Next) -> Response<Body> {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(HTML_CSP));
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ValidatedCreateRequest {
    ciphertext_size_bytes: u64,
    expires_in_seconds: u64,
}

fn validate_create_request(
    config: &AppConfig,
    payload: &CreateSecretRequest,
) -> Result<ValidatedCreateRequest, ApiError> {
    if payload.ciphertext.is_empty() {
        return Err(ApiError::bad_request("ciphertext must not be empty"));
    }

    let ciphertext_size_bytes = u64::try_from(payload.ciphertext.len())
        .map_err(|_| ApiError::bad_request("ciphertext is too large"))?;
    if ciphertext_size_bytes > config.max_ciphertext_bytes {
        return Err(ApiError::bad_request(
            "ciphertext exceeds the configured size limit",
        ));
    }

    if payload.nonce.is_empty() {
        return Err(ApiError::bad_request("nonce must not be empty"));
    }

    if u64::try_from(payload.nonce.len())
        .map_err(|_| ApiError::bad_request("nonce is too large"))?
        > config.max_ciphertext_bytes
    {
        return Err(ApiError::bad_request(
            "nonce exceeds the configured size limit",
        ));
    }

    if !is_allowed_ttl(payload.expires_in_seconds) {
        return Err(ApiError::bad_request(
            "expires_in_seconds is not an allowed TTL",
        ));
    }

    if payload.expires_in_seconds > config.max_ttl_seconds {
        return Err(ApiError::bad_request(
            "expires_in_seconds exceeds the configured TTL limit",
        ));
    }

    Ok(ValidatedCreateRequest {
        ciphertext_size_bytes,
        expires_in_seconds: payload.expires_in_seconds,
    })
}

fn ensure_create_enabled(config: &AppConfig) -> Result<(), ApiError> {
    if !config.enable_create {
        return Err(ApiError::service_unavailable(
            "secret creation is temporarily disabled",
        ));
    }

    Ok(())
}

fn enforce_global_create_quotas(
    state: &AppState,
    now_timestamp: i64,
    new_secret_size_bytes: u64,
) -> Result<(), ApiError> {
    let ActiveSecretStats {
        active_secret_count,
        active_storage_bytes,
    } = state
        .secret_store
        .active_secret_stats(now_timestamp)
        .map_err(|error| ApiError::internal(format!("failed to check global quotas: {error}")))?;

    if active_secret_count >= state.config.global_max_active_secrets {
        return Err(ApiError::service_unavailable(
            "global active secret quota has been reached",
        ));
    }

    let projected_storage_bytes = active_storage_bytes
        .checked_add(new_secret_size_bytes)
        .ok_or_else(|| ApiError::internal("global storage quota calculation overflowed"))?;

    if projected_storage_bytes > state.config.global_max_storage_bytes {
        return Err(ApiError::service_unavailable(
            "global storage quota has been reached",
        ));
    }

    Ok(())
}

fn check_create_rate_limit_hook(
    state: &AppState,
    requester_ip_hash: Option<&str>,
    now_timestamp: i64,
) -> Result<(), ApiError> {
    let Some(requester_ip_hash) = requester_ip_hash else {
        return Ok(());
    };

    let minute_bucket_kind = RateLimitBucket::CreateMinute;
    let minute_bucket = minute_bucket_kind.bucket_for_timestamp(now_timestamp);
    let minute_key = minute_bucket_kind.key(requester_ip_hash);
    let minute_count = state
        .secret_store
        .increment_rate_limit_counter(&minute_key, minute_bucket)
        .map_err(|error| {
            ApiError::internal(format!("failed to update create rate limit: {error}"))
        })?;

    if minute_count > state.config.create_rate_limit_per_minute {
        return Err(ApiError::too_many_requests());
    }

    let hour_bucket_kind = RateLimitBucket::CreateHour;
    let hour_bucket = hour_bucket_kind.bucket_for_timestamp(now_timestamp);
    let hour_key = hour_bucket_kind.key(requester_ip_hash);
    let hour_count = state
        .secret_store
        .increment_rate_limit_counter(&hour_key, hour_bucket)
        .map_err(|error| {
            ApiError::internal(format!("failed to update create rate limit: {error}"))
        })?;

    if hour_count > state.config.create_rate_limit_per_hour {
        return Err(ApiError::too_many_requests());
    }

    Ok(())
}

fn check_read_rate_limit(
    state: &AppState,
    requester_ip_hash: Option<&str>,
    now_timestamp: i64,
) -> Result<(), ApiError> {
    let Some(requester_ip_hash) = requester_ip_hash else {
        return Ok(());
    };

    let minute_bucket_kind = RateLimitBucket::ReadMinute;
    let minute_bucket = minute_bucket_kind.bucket_for_timestamp(now_timestamp);
    let minute_key = minute_bucket_kind.key(requester_ip_hash);
    let minute_count = state
        .secret_store
        .increment_rate_limit_counter(&minute_key, minute_bucket)
        .map_err(|error| {
            ApiError::internal(format!("failed to update read rate limit: {error}"))
        })?;

    if minute_count > state.config.read_rate_limit_per_minute {
        return Err(ApiError::too_many_requests());
    }

    Ok(())
}

#[derive(Debug, serde::Serialize)]
struct TurnstileVerifyRequest<'a> {
    secret: &'a str,
    response: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    remoteip: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct TurnstileVerifyResponse {
    success: bool,
    #[serde(rename = "error-codes", default)]
    error_codes: Vec<String>,
}

async fn verify_turnstile(
    state: &AppState,
    client_ip: Option<std::net::IpAddr>,
    payload: &CreateSecretRequest,
) -> Result<(), ApiError> {
    if payload.turnstile_token.is_empty() {
        return Err(ApiError::bad_request("turnstile_token must not be empty"));
    }

    let response = state
        .turnstile_client
        .request(
            HyperRequest::post(&state.config.turnstile_verify_url)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Full::new(Bytes::from(
                    serde_urlencoded::to_string(TurnstileVerifyRequest {
                        secret: &state.config.turnstile_secret_key,
                        response: &payload.turnstile_token,
                        remoteip: client_ip.map(|ip| ip.to_string()),
                    })
                    .map_err(|error| {
                        ApiError::internal(format!(
                            "failed to encode turnstile verification payload: {error}"
                        ))
                    })?,
                )))
                .map_err(|error| {
                    ApiError::internal(format!(
                        "failed to build turnstile verification request: {error}"
                    ))
                })?,
        )
        .await
        .map_err(|error| {
            ApiError::service_unavailable(format!("turnstile verification is unavailable: {error}"))
        })?;

    let response_body = response.into_body().collect().await.map_err(|error| {
        ApiError::service_unavailable(format!("turnstile verification is unavailable: {error}"))
    })?;
    let verification: TurnstileVerifyResponse = serde_json::from_slice(&response_body.to_bytes())
        .map_err(|error| {
        ApiError::service_unavailable(format!("turnstile verification is unavailable: {error}"))
    })?;

    if !verification.success {
        let details = if verification.error_codes.is_empty() {
            "unknown error".to_owned()
        } else {
            verification.error_codes.join(",")
        };

        return Err(ApiError::bad_request(format!(
            "turnstile verification failed: {details}"
        )));
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
    use std::time::{SystemTime, UNIX_EPOCH};

    use axum::{
        Json,
        body::Body,
        extract::ConnectInfo,
        http::{Method, Request, StatusCode, header},
        response::IntoResponse,
        routing::post,
    };
    use serde_json::Value;
    use tower::util::ServiceExt;

    use super::{build_router, current_timestamp, matched_path_or_uri};
    use crate::{
        config::AppConfig,
        db::{Database, NewSecretRecord},
        request_context::ClientIp,
        secret::{generate_secret_reference, hash_delete_token},
    };

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
    async fn index_page_exposes_browser_encryption_shell() {
        let (_guard, app, _database) = test_router("index-page", AppConfig::default());

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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let html = String::from_utf8(body.to_vec()).expect("body should be utf-8");

        assert!(html.contains(r#"id="create-app""#));
        assert!(html.contains(r#"data-max-secret-bytes="16384""#));
        assert!(html.contains(r#"data-turnstile-site-key="test-turnstile-site-key""#));
        assert!(html.contains("challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"));
        assert!(html.contains(r#"src="/static/app.js?v="#));
        assert!(html.contains(r#"href="/static/app.css?v="#));
        assert!(html.contains("Share a secret."));
        assert!(html.contains(
            "<strong>psst</strong> creates one-time secret links with client-side encryption."
        ));
        assert!(html.contains("Create psst link"));
        assert!(html.contains("Delete now"));
        assert!(
            html.contains("nothing can be recovered after read, expiration, or early deletion")
        );
        assert!(html.contains("The recipient must receive the full link, including the fragment."));
    }

    #[tokio::test]
    async fn read_page_exposes_secret_id_for_browser_decryption() {
        let (_guard, app, _database) = test_router("read-page", AppConfig::default());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/s/test-secret-id")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let html = String::from_utf8(body.to_vec()).expect("body should be utf-8");

        assert!(html.contains(r#"id="read-app""#));
        assert!(html.contains(r#"data-secret-id="test-secret-id""#));
        assert!(html.contains("Click to decrypt the secret"));
        assert!(html.contains(r#"id="decrypt-secret-button""#));
        assert!(html.contains(r#"id="copy-secret-button""#));
        assert!(html.contains(r#"src="/static/app.js?v="#));
        assert!(
            html.contains(
                "<strong>psst</strong> cannot help if the fragment key is missing or wrong"
            )
        );
    }

    #[tokio::test]
    async fn static_assets_are_served_from_the_application() {
        let (_guard, app, _database) = test_router("static-assets", AppConfig::default());

        let css_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/static/app.css")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");
        let js_response = app
            .oneshot(
                Request::builder()
                    .uri("/static/app.js")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(css_response.status(), StatusCode::OK);
        assert_eq!(
            css_response.headers().get(header::CONTENT_TYPE),
            Some(&header_value("text/css; charset=utf-8"))
        );

        assert_eq!(js_response.status(), StatusCode::OK);
        assert_eq!(
            js_response.headers().get(header::CONTENT_TYPE),
            Some(&header_value("text/javascript; charset=utf-8"))
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
        let oversized_body = format!(
            r#"{{"ciphertext":"{}","nonce":"n","expires_in_seconds":1,"turnstile_token":"t"}}"#,
            "a".repeat(40_000)
        );

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
        let verifier = start_turnstile_test_server(TurnstileScenario::Success).await;
        let mut config = AppConfig::default();
        config.turnstile_verify_url = verifier.url.clone();
        let expected_requester_ip_hash = ClientIp("203.0.113.10".parse().expect("ip should parse"))
            .hashed_identifier(&config.ip_hash_salt);
        let (_guard, app, database) = test_router("create-success", config);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/create")
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 12345))))
                    .header("cf-connecting-ip", "203.0.113.10")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"ciphertext":"ciphertext-value","nonce":"nonce-value","expires_in_seconds":86400,"turnstile_token":"valid-turnstile-token"}"#,
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
                "SELECT ciphertext, nonce, delete_token_hash, requester_ip_hash FROM secrets WHERE id = ?1",
                [secret_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .expect("secret should be stored");

        assert_eq!(stored.0, "ciphertext-value");
        assert_eq!(stored.1, "nonce-value");
        assert_eq!(stored.2, hash_delete_token(delete_token));
        assert_eq!(stored.3, Some(expected_requester_ip_hash));
    }

    #[tokio::test]
    async fn create_route_rejects_failed_turnstile_verification() {
        let verifier = start_turnstile_test_server(TurnstileScenario::Failure).await;
        let mut config = AppConfig::default();
        config.turnstile_verify_url = verifier.url.clone();
        let (_guard, app, _database) = test_router("turnstile-failure", config);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/create")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"ciphertext":"ciphertext-value","nonce":"nonce-value","expires_in_seconds":86400,"turnstile_token":"invalid-turnstile-token"}"#,
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_route_returns_503_when_turnstile_verifier_is_unavailable() {
        let mut config = AppConfig::default();
        config.turnstile_verify_url = "http://127.0.0.1:9/siteverify".to_owned();
        let (_guard, app, _database) = test_router("turnstile-unavailable", config);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/create")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"ciphertext":"ciphertext-value","nonce":"nonce-value","expires_in_seconds":86400,"turnstile_token":"valid-turnstile-token"}"#,
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
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
    async fn create_route_rejects_ciphertext_above_configured_limit() {
        let mut config = AppConfig::default();
        config.max_ciphertext_bytes = 10;
        let (_guard, app, _database) = test_router("ciphertext-limit", config);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/create")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"ciphertext":"ciphertext-value","nonce":"nonce-value","expires_in_seconds":900,"turnstile_token":"dummy-token"}"#,
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_route_rejects_ttl_above_configured_limit() {
        let mut config = AppConfig::default();
        config.default_ttl_seconds = 3600;
        config.max_ttl_seconds = 3600;
        let (_guard, app, _database) = test_router("ttl-limit", config);

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

    #[tokio::test]
    async fn create_route_rejects_when_minute_rate_limit_is_exceeded() {
        let verifier = start_turnstile_test_server(TurnstileScenario::Success).await;
        let mut config = AppConfig::default();
        config.turnstile_verify_url = verifier.url.clone();
        config.create_rate_limit_per_minute = 1;
        let (_guard, app, _database) = test_router("create-minute-rate-limit", config);

        for expected_status in [StatusCode::OK, StatusCode::TOO_MANY_REQUESTS] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/api/create")
                        .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 12345))))
                        .header("cf-connecting-ip", "203.0.113.10")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            r#"{"ciphertext":"ciphertext-value","nonce":"nonce-value","expires_in_seconds":86400,"turnstile_token":"valid-turnstile-token"}"#,
                        ))
                        .expect("request should build"),
                )
                .await
                .expect("router should respond");

            assert_eq!(response.status(), expected_status);
        }
    }

    #[tokio::test]
    async fn create_route_rejects_when_hour_rate_limit_is_exceeded() {
        let verifier = start_turnstile_test_server(TurnstileScenario::Success).await;
        let mut config = AppConfig::default();
        config.turnstile_verify_url = verifier.url.clone();
        config.create_rate_limit_per_minute = 10;
        config.create_rate_limit_per_hour = 1;
        let (_guard, app, _database) = test_router("create-hour-rate-limit", config);

        for expected_status in [StatusCode::OK, StatusCode::TOO_MANY_REQUESTS] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/api/create")
                        .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 12345))))
                        .header("cf-connecting-ip", "203.0.113.10")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            r#"{"ciphertext":"ciphertext-value","nonce":"nonce-value","expires_in_seconds":86400,"turnstile_token":"valid-turnstile-token"}"#,
                        ))
                        .expect("request should build"),
                )
                .await
                .expect("router should respond");

            assert_eq!(response.status(), expected_status);
        }
    }

    #[tokio::test]
    async fn create_route_allows_multiple_requests_without_client_ip_context() {
        let verifier = start_turnstile_test_server(TurnstileScenario::Success).await;
        let mut config = AppConfig::default();
        config.turnstile_verify_url = verifier.url.clone();
        config.create_rate_limit_per_minute = 1;
        config.create_rate_limit_per_hour = 1;
        let (_guard, app, _database) = test_router("create-no-client-ip", config);

        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/api/create")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            r#"{"ciphertext":"ciphertext-value","nonce":"nonce-value","expires_in_seconds":86400,"turnstile_token":"valid-turnstile-token"}"#,
                        ))
                        .expect("request should build"),
                )
                .await
                .expect("router should respond");

            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn create_route_global_quota_still_returns_503_with_client_ip_context() {
        let mut config = AppConfig::default();
        config.global_max_active_secrets = 1;
        config.create_rate_limit_per_minute = 1;
        config.create_rate_limit_per_hour = 1;
        let (_guard, app, database) = test_router("active-secret-quota-with-ip", config);
        let _existing = insert_test_secret(
            &database,
            "ciphertext-existing",
            "nonce-existing",
            current_timestamp().expect("current timestamp should exist") + 3600,
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/create")
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 12345))))
                    .header("cf-connecting-ip", "203.0.113.10")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"ciphertext":"ciphertext-value","nonce":"nonce-value","expires_in_seconds":900,"turnstile_token":"dummy-token"}"#,
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn create_route_rejects_when_global_active_secret_quota_is_reached() {
        let mut config = AppConfig::default();
        config.global_max_active_secrets = 1;
        let (_guard, app, database) = test_router("active-secret-quota", config);
        let _existing = insert_test_secret(
            &database,
            "ciphertext-existing",
            "nonce-existing",
            current_timestamp().expect("current timestamp should exist") + 3600,
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/create")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"ciphertext":"ciphertext-value","nonce":"nonce-value","expires_in_seconds":900,"turnstile_token":"dummy-token"}"#,
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn create_route_rejects_when_global_storage_quota_is_reached() {
        let mut config = AppConfig::default();
        config.global_max_storage_bytes = 10;
        let (_guard, app, _database) = test_router("storage-quota", config);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/create")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"ciphertext":"ciphertext-value","nonce":"nonce-value","expires_in_seconds":900,"turnstile_token":"dummy-token"}"#,
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn read_route_returns_secret_and_consumes_it() {
        let (_guard, app, database) = test_router("read-success", AppConfig::default());
        let generated = insert_test_secret(
            &database,
            "ciphertext-read",
            "nonce-read",
            current_timestamp().expect("current timestamp should exist") + 3600,
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/secrets/{}", generated.secret_id))
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let json: Value = serde_json::from_slice(&body).expect("body should be JSON");

        assert_eq!(
            json.get("ciphertext").and_then(Value::as_str),
            Some("ciphertext-read")
        );
        assert_eq!(
            json.get("nonce").and_then(Value::as_str),
            Some("nonce-read")
        );

        let connection = database
            .open_connection()
            .expect("database connection should open");
        let remaining: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM secrets WHERE id = ?1",
                [generated.secret_id.as_str()],
                |row| row.get(0),
            )
            .expect("count query should succeed");

        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn read_route_returns_404_on_second_read() {
        let (_guard, app, database) = test_router("read-twice", AppConfig::default());
        let generated = insert_test_secret(
            &database,
            "ciphertext-read-twice",
            "nonce-read-twice",
            current_timestamp().expect("current timestamp should exist") + 3600,
        );

        let first_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/secrets/{}", generated.secret_id))
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");
        let second_response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/secrets/{}", generated.secret_id))
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(first_response.status(), StatusCode::OK);
        assert_eq!(second_response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn read_route_rejects_when_minute_rate_limit_is_exceeded() {
        let mut config = AppConfig::default();
        config.read_rate_limit_per_minute = 1;
        let (_guard, app, database) = test_router("read-minute-rate-limit", config);
        let now_timestamp = current_timestamp().expect("current timestamp should exist");
        let first_secret =
            insert_test_secret(&database, "ciphertext-one", "nonce-one", now_timestamp + 60);
        let second_secret =
            insert_test_secret(&database, "ciphertext-two", "nonce-two", now_timestamp + 60);

        let request_for = |secret_id: &str| {
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/secrets/{secret_id}"))
                .extension(ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    12345,
                ))))
                .header("cf-connecting-ip", "203.0.113.10")
                .body(Body::empty())
                .expect("request should build")
        };

        let first_response = app
            .clone()
            .oneshot(request_for(&first_secret.secret_id))
            .await
            .expect("first read should respond");
        let second_response = app
            .oneshot(request_for(&second_secret.secret_id))
            .await
            .expect("second read should respond");

        assert_eq!(first_response.status(), StatusCode::OK);
        assert_eq!(second_response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn read_route_allows_multiple_requests_without_client_ip_context() {
        let mut config = AppConfig::default();
        config.read_rate_limit_per_minute = 1;
        let (_guard, app, database) = test_router("read-no-client-ip", config);
        let now_timestamp = current_timestamp().expect("current timestamp should exist");
        let first_secret = insert_test_secret(
            &database,
            "ciphertext-three",
            "nonce-three",
            now_timestamp + 60,
        );
        let second_secret = insert_test_secret(
            &database,
            "ciphertext-four",
            "nonce-four",
            now_timestamp + 60,
        );

        for secret_id in [&first_secret.secret_id, &second_secret.secret_id] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri(format!("/api/secrets/{secret_id}"))
                        .body(Body::empty())
                        .expect("request should build"),
                )
                .await
                .expect("router should respond");

            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn read_route_returns_404_for_expired_secret() {
        let (_guard, app, database) = test_router("read-expired", AppConfig::default());
        let generated = insert_test_secret(
            &database,
            "ciphertext-expired",
            "nonce-expired",
            current_timestamp().expect("current timestamp should exist") - 1,
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/secrets/{}", generated.secret_id))
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let connection = database
            .open_connection()
            .expect("database connection should open");
        let remaining: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM secrets WHERE id = ?1",
                [generated.secret_id.as_str()],
                |row| row.get(0),
            )
            .expect("count query should succeed");

        assert_eq!(remaining, 1);
    }

    #[tokio::test]
    async fn read_route_returns_404_for_unknown_secret() {
        let (_guard, app, _database) = test_router("read-missing", AppConfig::default());

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/secrets/does-not-exist")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_route_deletes_secret_with_matching_token() {
        let (_guard, app, database) = test_router("delete-success", AppConfig::default());
        let generated = insert_test_secret(
            &database,
            "ciphertext-delete",
            "nonce-delete",
            current_timestamp().expect("current timestamp should exist") + 3600,
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/delete/{}", generated.secret_id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"delete_token":"{}"}}"#,
                        generated.delete_token
                    )))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let json: Value = serde_json::from_slice(&body).expect("body should be JSON");
        assert_eq!(json.get("deleted").and_then(Value::as_bool), Some(true));

        let connection = database
            .open_connection()
            .expect("database connection should open");
        let remaining: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM secrets WHERE id = ?1",
                [generated.secret_id.as_str()],
                |row| row.get(0),
            )
            .expect("count query should succeed");

        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn delete_route_returns_404_for_invalid_token() {
        let (_guard, app, database) = test_router("delete-invalid-token", AppConfig::default());
        let generated = insert_test_secret(
            &database,
            "ciphertext-delete-invalid",
            "nonce-delete-invalid",
            current_timestamp().expect("current timestamp should exist") + 3600,
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/delete/{}", generated.secret_id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"delete_token":"wrong-token"}"#))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let connection = database
            .open_connection()
            .expect("database connection should open");
        let remaining: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM secrets WHERE id = ?1",
                [generated.secret_id.as_str()],
                |row| row.get(0),
            )
            .expect("count query should succeed");

        assert_eq!(remaining, 1);
    }

    #[tokio::test]
    async fn delete_route_returns_404_for_missing_secret() {
        let (_guard, app, _database) = test_router("delete-missing", AppConfig::default());

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/delete/does-not-exist")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"delete_token":"some-token"}"#))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
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

    fn test_router(
        prefix: &str,
        mut config: AppConfig,
    ) -> (TestTempDirGuard, axum::Router, Database) {
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

        std::env::temp_dir().join(format!("psst-rs-http-{prefix}-{unique}"))
    }

    impl Drop for TestTempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct TestTempDirGuard(std::path::PathBuf);

    #[derive(Clone, Copy)]
    enum TurnstileScenario {
        Success,
        Failure,
    }

    struct TurnstileTestServer {
        url: String,
        handle: tokio::task::JoinHandle<()>,
    }

    impl Drop for TurnstileTestServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    async fn start_turnstile_test_server(scenario: TurnstileScenario) -> TurnstileTestServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should exist");
        let app = axum::Router::new()
            .route("/siteverify", post(turnstile_test_handler))
            .with_state(scenario);
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("turnstile test server should run");
        });

        TurnstileTestServer {
            url: format!("http://{addr}/siteverify"),
            handle,
        }
    }

    async fn turnstile_test_handler(
        axum::extract::State(scenario): axum::extract::State<TurnstileScenario>,
        axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>,
    ) -> impl IntoResponse {
        let success = matches!(scenario, TurnstileScenario::Success)
            && form.get("secret").map(String::as_str) == Some("test-turnstile-secret-key")
            && form.get("response").map(String::as_str) == Some("valid-turnstile-token");

        Json(serde_json::json!({
            "success": success,
            "error-codes": if success {
                Vec::<String>::new()
            } else {
                vec!["invalid-input-response".to_owned()]
            },
        }))
    }

    fn insert_test_secret(
        database: &Database,
        ciphertext: &str,
        nonce: &str,
        expires_at: i64,
    ) -> crate::secret::GeneratedSecretReference {
        let store = crate::db::SecretStore::new(database.clone());
        let generated = generate_secret_reference();
        let now_timestamp = current_timestamp().expect("current timestamp should exist");

        store
            .insert_secret(&NewSecretRecord {
                id: generated.secret_id.clone(),
                ciphertext: ciphertext.to_owned(),
                nonce: nonce.to_owned(),
                created_at: now_timestamp,
                expires_at,
                delete_token_hash: hash_delete_token(&generated.delete_token),
                size_bytes: u64::try_from(ciphertext.len()).expect("ciphertext len should fit"),
                requester_ip_hash: None,
            })
            .expect("secret insertion should succeed");

        generated
    }
}
