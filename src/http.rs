use std::{
    fmt::Write as _,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, MatchedPath, Path, Request, State},
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
use tracing::info;

use crate::{
    config::AppConfig,
    db::{ActiveSecretStats, Database, NewSecretRecord, SecretStore},
    request_context::ClientIp,
    secret::{
        ALLOWED_TTL_SECONDS, CreateSecretRequest, CreateSecretResponse, DeleteSecretRequest,
        DeleteSecretResponse, ReadSecretResponse, generate_secret_reference, hash_delete_token,
        is_allowed_ttl,
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

async fn about() -> Html<String> {
    Html(render_about_page())
}

async fn read_secret_page(Path(secret_id): Path<String>) -> Html<String> {
    Html(render_read_page(&secret_id))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn static_app_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../static/app.css"),
    )
}

async fn static_app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../static/app.js"),
    )
}

async fn create_secret_stub(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(payload): Json<CreateSecretRequest>,
) -> Result<Json<CreateSecretResponse>, ApiError> {
    let now_timestamp = current_timestamp()?;
    let validated = validate_create_request(&state.config, &payload)?;

    ensure_create_enabled(&state.config)?;
    enforce_global_create_quotas(&state, now_timestamp, validated.ciphertext_size_bytes)?;
    check_create_rate_limit_hook(&state)?;
    verify_turnstile_hook(&payload)?;

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

async fn read_secret(
    axum::extract::State(state): axum::extract::State<AppState>,
    Path(secret_id): Path<String>,
) -> Result<Json<ReadSecretResponse>, ApiError> {
    let now_timestamp = current_timestamp()?;
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
    let public_base_url = escape_html_attribute(&config.public_base_url);
    let mut ttl_options = String::new();

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

    format!(
        r#"<!doctype html>
<html lang="fr">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>secret-rs</title>
    <link rel="stylesheet" href="/static/app.css">
    <script src="/static/app.js" defer></script>
  </head>
  <body>
    <main class="layout" id="create-app" data-public-base-url="{public_base_url}" data-max-secret-bytes="{max_secret_bytes}" data-enable-create="{enable_create}">
      <header class="hero">
        <p class="eyebrow">secret-rs</p>
        <h1>Partager un secret sans envoyer la cle au serveur.</h1>
        <p class="lede">Le secret est chiffre dans le navigateur, lu une seule fois, puis supprime.</p>
      </header>

      <section class="panel">
        <form id="create-form" novalidate>
          <label class="field">
            <span>Secret</span>
            <textarea id="secret-input" name="secret" rows="10" placeholder="Collez le mot de passe, la phrase de recuperation ou la note confidentielle."></textarea>
          </label>

          <div class="row">
            <label class="field compact">
              <span>Expiration</span>
              <select id="ttl-select" name="expires_in_seconds">{ttl_options}</select>
            </label>
            <div class="field compact">
              <span>Taille</span>
              <p class="metric"><strong id="secret-size">0</strong> / {max_secret_bytes} octets UTF-8</p>
            </div>
          </div>

          <div class="actions">
            <button id="create-button" type="submit">Chiffrer et creer le lien</button>
          </div>
        </form>

        <p class="hint">Limite : {max_secret_bytes} octets UTF-8 avant chiffrement. La cle reste dans le fragment <code>#...</code>.</p>
        <p class="status" id="create-status" role="status" aria-live="polite"></p>
      </section>

      <section class="panel" id="create-result" hidden>
        <h2>Lien de partage</h2>
        <p>Le destinataire doit recevoir le lien complet, fragment inclus.</p>
        <label class="field">
          <span>Lien</span>
          <input id="share-link" type="text" readonly>
        </label>
        <div class="actions">
          <button id="copy-link-button" type="button">Copier</button>
        </div>
        <p class="status" id="copy-status" role="status" aria-live="polite"></p>
      </section>

      <footer class="footer">
        <a href="/about">A propos</a>
      </footer>
    </main>
  </body>
</html>"#,
        max_secret_bytes = config.max_secret_bytes,
        enable_create = config.enable_create,
    )
}

fn render_about_page() -> String {
    r#"<!doctype html>
<html lang="fr">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>A propos</title>
    <link rel="stylesheet" href="/static/app.css">
  </head>
  <body>
    <main class="layout prose">
      <header class="hero">
        <p class="eyebrow">A propos</p>
        <h1>Le serveur ne voit jamais la cle.</h1>
      </header>

      <section class="panel">
        <p>Le navigateur genere une cle AES-GCM, chiffre le secret localement puis n'envoie au serveur que le ciphertext et le nonce.</p>
        <p>Le lien final contient la cle uniquement dans le fragment d'URL, apres <code>#</code>. Le fragment n'est pas transmis au serveur lors des requetes HTTP.</p>
        <p>Quand le secret est lu avec succes, le serveur le supprime immediatement.</p>
      </section>

      <footer class="footer">
        <a href="/">Retour</a>
      </footer>
    </main>
  </body>
</html>"#
        .to_owned()
}

fn render_read_page(secret_id: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="fr">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Lire le secret</title>
    <link rel="stylesheet" href="/static/app.css">
    <script src="/static/app.js" defer></script>
  </head>
  <body>
    <main class="layout" id="read-app" data-secret-id="{}">
      <header class="hero">
        <p class="eyebrow">Lecture unique</p>
        <h1>Dechiffrement local du secret.</h1>
        <p class="lede">Le secret est recupere une fois, dechiffre dans le navigateur, puis retire du stockage.</p>
      </header>

      <section class="panel">
        <p class="status" id="read-status" role="status" aria-live="polite">Recuperation du secret...</p>
        <pre id="secret-output" hidden></pre>
      </section>

      <footer class="footer">
        <a href="/">Creer un autre lien</a>
      </footer>
    </main>
  </body>
</html>"#,
        escape_html_attribute(secret_id)
    )
}

fn ttl_label(ttl_seconds: u64) -> &'static str {
    match ttl_seconds {
        ttl if ttl == 15 * 60 => "15 minutes",
        ttl if ttl == 60 * 60 => "1 heure",
        ttl if ttl == 24 * 60 * 60 => "24 heures",
        ttl if ttl == 7 * 24 * 60 * 60 => "7 jours",
        _ => "TTL non supporte",
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

// Step 7 hook: rate limiting will be wired here without reshaping the handler.
fn check_create_rate_limit_hook(_state: &AppState) -> Result<(), ApiError> {
    Ok(())
}

// Step 7 hook: Turnstile verification will be wired here without reshaping the handler.
fn verify_turnstile_hook(payload: &CreateSecretRequest) -> Result<(), ApiError> {
    if payload.turnstile_token.is_empty() {
        return Err(ApiError::bad_request("turnstile_token must not be empty"));
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
        body::Body,
        http::{Method, Request, StatusCode, header},
    };
    use serde_json::Value;
    use tower::util::ServiceExt;

    use super::{build_router, current_timestamp, matched_path_or_uri};
    use crate::{
        config::AppConfig,
        db::{Database, NewSecretRecord},
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
        assert!(html.contains(r#"src="/static/app.js""#));
        assert!(html.contains(r#"href="/static/app.css""#));
        assert!(html.contains("Chiffrer et creer le lien"));
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
        assert!(html.contains("Recuperation du secret..."));
        assert!(html.contains(r#"src="/static/app.js""#));
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

        std::env::temp_dir().join(format!("secret-rs-http-{prefix}-{unique}"))
    }

    impl Drop for TestTempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct TestTempDirGuard(std::path::PathBuf);

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
