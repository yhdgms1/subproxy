mod bot;
mod headers;
mod script;
mod ssrf;
mod subscription;

use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::get};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use reqwest::Client;
use reqwest::header::CONTENT_TYPE;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tower::ServiceBuilder;
use tower_governor::{
    GovernorLayer, governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor,
};
use tower_http::cors::{Any, CorsLayer};

const VLESS_WHOAMI_TEMPLATE: &'static str = include_str!("./vless-templates/whoami.json");
const CONTENT_TYPE_JSON: &'static str = "application/json; charset=UTF-8";

#[derive(Clone)]
struct AppState {
    client: Client,
}

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new()
        .allow_methods([Method::GET])
        .allow_origin(Any);

    let governor_conf = GovernorConfigBuilder::default()
        .key_extractor(SmartIpKeyExtractor)
        .period(Duration::from_secs(60))
        .burst_size(10)
        .finish()
        .unwrap();

    let governor_limiter = governor_conf.limiter().clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(120));

        loop {
            interval.tick().await;
            governor_limiter.retain_recent();
        }
    });

    let state = AppState {
        client: subscription::client(),
    };

    let app = Router::new()
        .route("/whoami", get(whoami_handler))
        .route("/{host}/{path}/{headers}", get(sub_handler))
        .route("/{host}/{path}/{headers}/{script}", get(script_handler))
        .layer(middleware::from_fn(bot_middleware))
        .layer(ServiceBuilder::new().layer(cors))
        .layer(GovernorLayer::new(governor_conf))
        .with_state(state);

    let addr: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8080));

    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn bot_middleware(request: Request, next: Next) -> Response {
    let ua = request
        .headers()
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok());

    if bot::is_bot(ua) {
        return (StatusCode::IM_A_TEAPOT, "I'm a teapot").into_response();
    }

    next.run(request).await
}

#[axum::debug_handler]
async fn sub_handler(
    State(state): State<AppState>,
    Path((host, path, headers)): Path<(String, String, String)>,
) -> impl IntoResponse {
    match subscription::load(&state.client, &host, &path, &headers).await {
        Ok(subscription) => subscription.into_response(),
        Err(err) => subscription::error_response(err.title()),
    }
}

#[axum::debug_handler]
async fn script_handler(
    State(state): State<AppState>,
    Path((host, path, headers, script)): Path<(String, String, String, String)>,
) -> impl IntoResponse {
    let source = match script::decode(&script) {
        Ok(source) => source,
        Err(err) => return subscription::error_response(err.title()),
    };

    let subscription = match subscription::load(&state.client, &host, &path, &headers).await {
        Ok(subscription) => subscription,
        Err(err) => return subscription::error_response(err.title()),
    };

    match script::run(source, subscription).await {
        Ok(subscription) => subscription.into_response(),
        Err(err) => subscription::error_response(err.title()),
    }
}

#[axum::debug_handler]
async fn whoami_handler(headers: HeaderMap) -> impl IntoResponse {
    let res = Response::builder()
        .header(CONTENT_TYPE, CONTENT_TYPE_JSON)
        .status(StatusCode::OK);
    let mut headers_vec = Vec::new();

    for (name, value) in headers {
        if let Some(name) = name {
            let name_str = name.as_str().to_lowercase();

            if headers::is_allowed_whoami_header(&name_str) {
                if let Ok(value_str) = value.to_str() {
                    if !value_str.is_empty() {
                        headers_vec.push(name_str);
                        headers_vec.push(value_str.to_string());
                    }
                }
            }
        }
    }

    let json = match serde_json::to_string(&headers_vec) {
        Err(_) => return subscription::error_response("Ошибка сериализации"),
        Ok(val) => val,
    };

    let encoded = URL_SAFE.encode(json);

    return res
        .header("announce", "base64:0J3QsNC20LzQuCDQvdCwINGB0YLRgNC10LvQutGDINGB0L/RgNCw0LLQsCDQvtGCINGB0LXRgNCy0LXRgNCw")
        .header("profile-title", "base64:c3VicHJveHk=")
        .header("title", "auto")
        .body(VLESS_WHOAMI_TEMPLATE.replace("{{id}}", &encoded))
        .unwrap();
}
