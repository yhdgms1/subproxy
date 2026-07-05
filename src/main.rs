use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};
use axum::{Router, response::IntoResponse, routing::get};
use axum_extra::extract::Query;
use form_urlencoded::Serializer;
use reqwest::Client;
use serde::Deserialize;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};

const VLESS_CONFIG_TEMPLATE: &'static str = include_str!("./vless-config-template.json");
const HEADERS_WHITELIST: [&str; 9] = [
    "subscription-userinfo",
    "profile-update-interval", 
    "profile-title",
    "profile-web-page-url",
    "support-url",
    "announce",
    "announce-url",
    "content-type",
    "content-length"
];

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new()
        .allow_methods([Method::GET])
        .allow_origin(Any);

    let app = Router::new()
        .route("/get", get(get_handler))
        .route("/whoami", get(whoami_handler))
        .layer(ServiceBuilder::new().layer(cors));

    let addr: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8080));

    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[derive(Deserialize, Debug)]
struct GetHandlerQuery {
    host: String,
    path: String,
    headers: Vec<String>,
}

#[axum::debug_handler]
async fn get_handler(Query(params): Query<GetHandlerQuery>) -> impl IntoResponse {
    let GetHandlerQuery {
        host,
        path,
        headers,
    } = params;

    if headers.len() % 2 != 0 {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(String::new())
            .unwrap();
    }

    let mut header_map = HeaderMap::new();

    for chunk in headers.chunks_exact(2) {
        let name = chunk[0].to_string();

        if HEADERS_WHITELIST.contains(&&name.to_ascii_lowercase().as_str()) {
            let header_name = HeaderName::from_str(&name).unwrap();
            let header_value = HeaderValue::from_bytes(chunk[1].as_bytes()).unwrap();

            header_map.insert(header_name, header_value);
        }
    }

    let response = Client::new()
        .get(format!("https://{}/{}", host, path))
        .headers(header_map)
        .send()
        .await
        .unwrap();

    let mut res = Response::builder().status(StatusCode::OK);

    if let Some(headers) = res.headers_mut() {
        for (name, value) in response.headers() {
            headers.append(name, value.clone());
        }
    }

    return res.body(response.text().await.unwrap()).unwrap();
}

#[axum::debug_handler]
async fn whoami_handler(headers: HeaderMap) -> impl IntoResponse {
    let mut serializer = Serializer::new(String::new());

    for (name, value) in headers {
        if let Some(name) = name {
            let name_str = name.as_str().to_lowercase();

            if name_str == "user-agent" || name_str.starts_with("x-") {
                if let Ok(value_str) = value.to_str() {
                    if !value_str.is_empty() {
                        serializer.append_pair("headers", name_str.as_str());
                        serializer.append_pair("headers", value_str);
                    }
                }
            }
        }
    }

    let query = format!("?{}", serializer.finish());

    return Response::builder()
        .header("announce", "base64:0J3QsNC20LzQuCDQvdCwINGB0YLRgNC10LvQutGDINGB0L/RgNCw0LLQsCDQvtGCINGB0LXRgNCy0LXRgNCw")
        .header("profile-title", "base64:c3VicHJveHk=")
        .header("title", "auto")
        .status(StatusCode::OK)
        .body(VLESS_CONFIG_TEMPLATE.replace("{{id}}", &query))
        .unwrap();
}
