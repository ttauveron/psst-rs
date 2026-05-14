use std::time::Instant;

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
use serde::Deserialize;
use tracing::info;

use crate::{config::AppConfig, request_context::ClientIp};

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
}

#[derive(Debug, Deserialize)]
struct CreateSecretRequest {
    ciphertext: String,
    nonce: String,
    expires_in_seconds: u64,
    turnstile_token: String,
}

pub fn build_router(config: AppConfig) -> Router {
    let max_json_body_bytes =
        usize::try_from(config.max_ciphertext_bytes.saturating_add(4096)).unwrap_or(usize::MAX);
    let app_state = AppState {
        config: config.clone(),
    };

    Router::new()
        .route("/", get(index))
        .route("/about", get(about))
        .route("/abuse", get(abuse))
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

async fn abuse() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html lang="fr">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Abuse</title>
  </head>
  <body>
    <main>
      <h1>Abuse</h1>
      <p>Cette page servira au signalement des liens abusifs.</p>
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
) -> impl IntoResponse {
    let _shape_probe = (
        payload.ciphertext.len(),
        payload.nonce.len(),
        payload.expires_in_seconds,
        payload.turnstile_token.len(),
        state.config.max_ciphertext_bytes,
    );

    StatusCode::NOT_IMPLEMENTED
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

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode, header},
    };
    use tower::util::ServiceExt;

    use super::{build_router, matched_path_or_uri};
    use crate::config::AppConfig;

    #[tokio::test]
    async fn html_routes_include_security_headers() {
        let app = build_router(AppConfig::default());

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
        let app = build_router(AppConfig::default());

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
        let app = build_router(AppConfig::default());
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
}
