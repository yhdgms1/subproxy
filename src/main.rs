mod ssrf;

use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};
use axum::{Router, response::IntoResponse, extract::Path, routing::get};
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use reqwest::{Client, Url};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};

const VLESS_CONFIG_TEMPLATE: &'static str = include_str!("./vless-config-template.json");
const VLESS_ERROR_TEMPLATE: &'static str = include_str!("./vless-error-template.json");
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
        .route("/whoami", get(whoami_handler))
        .route("/{host}/{path}/{headers}", get(sub_handler))
        .layer(ServiceBuilder::new().layer(cors));

    let addr: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8080));

    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[axum::debug_handler]
async fn sub_handler(Path((host, path, headers)): Path<(String, String, String)>,) -> impl IntoResponse {
    let mut res = Response::builder().status(StatusCode::OK);

    let mut url = match Url::parse(&format!("https://{}", host)) {
        Err(_) => {
            return res.body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "%D0%9D%D0%B5%D0%B2%D0%B5%D1%80%D0%BD%D1%8B%D0%B9%20%D0%B0%D0%B4%D1%80%D0%B5%D1%81")).unwrap();
        },
        Ok(url) => url
    };

    url.set_path(&path);

    let host_str = match url.host_str() {
        None => {
            return res.body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "%D0%9D%D0%B5%D0%BA%D0%BE%D1%80%D1%80%D0%B5%D0%BA%D1%82%D0%BD%D1%8B%D0%B9%20%D1%85%D0%BE%D1%81%D1%82")).unwrap();
        },
        Some(host) => host
    };

    if !ssrf::is_host_safe(host_str).await {
        return res.body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "%D0%A5%D0%BE%D1%81%D1%82%20%D0%B7%D0%B0%D0%BF%D1%80%D0%B5%D1%89%D1%91%D0%BD")).unwrap();
    }

    let headers = match URL_SAFE.decode(headers) {
        Err(_) => {
            return res.body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "%D0%9E%D1%88%D0%B8%D0%B1%D0%BA%D0%B0%20%D0%B4%D0%B5%D0%BA%D0%BE%D0%B4%D0%B8%D1%80%D0%BE%D0%B2%D0%B0%D0%BD%D0%B8%D1%8F%20%D0%B7%D0%B0%D0%B3%D0%BE%D0%BB%D0%BE%D0%B2%D0%BA%D0%BE%D0%B2")).unwrap();
        },
        Ok(headers) => headers
    };

    let headers = match String::from_utf8(headers) {
        Err(_) => {
            return res.body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "%D0%9E%D1%88%D0%B8%D0%B1%D0%BA%D0%B0%20%D0%BA%D0%BE%D0%BD%D0%B2%D0%B5%D1%80%D1%82%D0%B0%D1%86%D0%B8%D0%B8%20%D0%B7%D0%B0%D0%B3%D0%BE%D0%BB%D0%BE%D0%B2%D0%BA%D0%BE%D0%B2")).unwrap();
        },
        Ok(headers) => headers
    };

    let headers: Vec<String> = match serde_json::from_str(&headers) {
        Err(_) => {
            return res.body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "%D0%9E%D1%88%D0%B8%D0%B1%D0%BA%D0%B0%20%D0%BF%D0%B0%D1%80%D1%81%D0%B8%D0%BD%D0%B3%D0%B0%20%D0%B7%D0%B0%D0%B3%D0%BE%D0%BB%D0%BE%D0%B2%D0%BA%D0%BE%D0%B2")).unwrap();
        },
        Ok(headers) => headers
    };

    if headers.len() % 2 != 0 {
       return res.body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "%D0%9D%D0%B5%D1%87%D1%91%D1%82%D0%BD%D0%BE%D0%B5%20%D0%BA%D0%BE%D0%BB%D0%B8%D1%87%D0%B5%D1%81%D1%82%D0%B2%D0%BE%20%D0%B7%D0%B0%D0%B3%D0%BE%D0%BB%D0%BE%D0%B2%D0%BA%D0%BE%D0%B2")).unwrap();
    }

    let mut header_map = HeaderMap::new();

    for chunk in headers.chunks_exact(2) {
        let header_name = match HeaderName::from_bytes(chunk[0].as_bytes()) {
            Err(_) => {
                return res.body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "%D0%9D%D0%B5%D0%BA%D0%BE%D1%80%D1%80%D0%B5%D0%BA%D1%82%D0%BD%D0%BE%D0%B5%20%D0%B8%D0%BC%D1%8F%20%D0%B7%D0%B0%D0%B3%D0%BE%D0%BB%D0%BE%D0%B2%D0%BA%D0%B0")).unwrap();
            },
            Ok(val) => val
        };

        let header_value = match HeaderValue::from_bytes(chunk[1].as_bytes()) {
            Err(_) => {
                return res.body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "%D0%9D%D0%B5%D0%BA%D0%BE%D1%80%D1%80%D0%B5%D0%BA%D1%82%D0%BD%D0%BE%D0%B5%20%D0%B7%D0%BD%D0%B0%D1%87%D0%B5%D0%BD%D0%B8%D0%B5%20%D0%B7%D0%B0%D0%B3%D0%BE%D0%BB%D0%BE%D0%B2%D0%BA%D0%B0")).unwrap();
            },
            Ok(val) => val
        };

        header_map.insert(header_name, header_value);
    }

    let response = match Client::new()
        .get(url)
        .headers(header_map)
        .send()
        .await {
            Err(_) => {
                return res.body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "%D0%9E%D1%88%D0%B8%D0%B1%D0%BA%D0%B0%20%D0%BE%D1%82%D0%BF%D1%80%D0%B0%D0%B2%D0%BA%D0%B8%20%D0%B7%D0%B0%D0%BF%D1%80%D0%BE%D1%81%D0%B0")).unwrap();
            },
            Ok(val) => val
        };

    if let Some(headers) = res.headers_mut() {
        for (name, value) in response.headers() {     
            if HEADERS_WHITELIST.contains(&name.to_string().to_ascii_lowercase().as_str()) {
                headers.append(name, value.clone());
            }
        }
    }

    return res.body(response.text().await.unwrap()).unwrap();
}

#[axum::debug_handler]
async fn whoami_handler(headers: HeaderMap) -> impl IntoResponse {
    let res = Response::builder().status(StatusCode::OK);
    let mut headers_vec = Vec::new();

    for (name, value) in headers {
        if let Some(name) = name {
            let name_str = name.as_str().to_lowercase();

            if name_str == "user-agent" || name_str.starts_with("x-") {
                if name_str != "x-real-ip" && name_str != "x-forwarded-for" && name_str != "x-forwarded-proto" && name_str != "x-forwarded-host" && name_str != "x-forwarded-port" {
                    if let Ok(value_str) = value.to_str() {
                        if !value_str.is_empty() {
                            headers_vec.push(name_str);
                            headers_vec.push(value_str.to_string());
                        }
                    }
                }
            }
        }
    }

    let json = match serde_json::to_string(&headers_vec) {
        Err(_) => {
            return res.body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "%D0%9E%D1%88%D0%B8%D0%B1%D0%BA%D0%B0%20%D1%81%D0%B5%D1%80%D0%B8%D0%B0%D0%BB%D0%B8%D0%B7%D0%B0%D1%86%D0%B8%D0%B8")).unwrap();
        },
        Ok(val) => val
    };

    let encoded = URL_SAFE.encode(json);

    return res
        .header("announce", "base64:0J3QsNC20LzQuCDQvdCwINGB0YLRgNC10LvQutGDINGB0L/RgNCw0LLQsCDQvtGCINGB0LXRgNCy0LXRgNCw")
        .header("profile-title", "base64:c3VicHJveHk=")
        .header("title", "auto")
        .body(VLESS_CONFIG_TEMPLATE.replace("{{id}}", &encoded))
        .unwrap();
}
