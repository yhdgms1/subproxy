mod headers;
mod ssrf;

use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};
use axum::{Router, extract::Path, response::IntoResponse, routing::get};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use reqwest::header::CONTENT_TYPE;
use reqwest::redirect::Policy;
use reqwest::{Client, Url};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tower::ServiceBuilder;
use tower_governor::{
    GovernorLayer, governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor,
};
use tower_http::cors::{Any, CorsLayer};

const VLESS_WHOAMI_TEMPLATE: &'static str = include_str!("./vless-templates/whoami.json");
const VLESS_ERROR_TEMPLATE: &'static str = include_str!("./vless-templates/error.json");
const CONTENT_TYPE_JSON: &'static str = "application/json; charset=UTF-8";

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

    let app = Router::new()
        .route("/whoami", get(whoami_handler))
        .route("/{host}/{path}/{headers}", get(sub_handler))
        .layer(ServiceBuilder::new().layer(cors))
        .layer(GovernorLayer::new(governor_conf));

    let addr: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8080));

    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[axum::debug_handler]
async fn sub_handler(
    Path((host, path, headers)): Path<(String, String, String)>,
) -> impl IntoResponse {
    let mut res = Response::builder().status(StatusCode::OK);

    if headers.len() > 2 * 1024 {
        return res
            .header(CONTENT_TYPE, CONTENT_TYPE_JSON)
            .body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "Размер заголовков слишком велик"))
            .unwrap();
    }

    let mut url = match Url::parse(&format!("https://{}", host)) {
        Err(_) => {
            return res
                .header(CONTENT_TYPE, CONTENT_TYPE_JSON)
                .body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "Неверный адрес"))
                .unwrap();
        }
        Ok(url) => url,
    };

    url.set_path(&path);

    let host_str = match url.host_str() {
        None => {
            return res
                .header(CONTENT_TYPE, CONTENT_TYPE_JSON)
                .body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "Некорректный хост"))
                .unwrap();
        }
        Some(host) => host,
    };

    if !ssrf::is_host_safe(host_str).await {
        return res
            .header(CONTENT_TYPE, CONTENT_TYPE_JSON)
            .body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "Хост запрещён"))
            .unwrap();
    }

    let headers = match URL_SAFE.decode(headers) {
        Err(_) => {
            return res
                .header(CONTENT_TYPE, CONTENT_TYPE_JSON)
                .body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "Ошибка декодирования заголовков"))
                .unwrap();
        }
        Ok(headers) => headers,
    };

    let headers = match String::from_utf8(headers) {
        Err(_) => {
            return res
                .header(CONTENT_TYPE, CONTENT_TYPE_JSON)
                .body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "Ошибка конвертации заголовков"))
                .unwrap();
        }
        Ok(headers) => headers,
    };

    let headers: Vec<String> = match serde_json::from_str(&headers) {
        Err(_) => {
            return res
                .header(CONTENT_TYPE, CONTENT_TYPE_JSON)
                .body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "Ошибка парсинга заголовков"))
                .unwrap();
        }
        Ok(headers) => headers,
    };

    if headers.len() % 2 != 0 {
        return res
            .header(CONTENT_TYPE, CONTENT_TYPE_JSON)
            .body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "Нечётное количество заголовков"))
            .unwrap();
    }

    let mut header_map = HeaderMap::new();

    for chunk in headers.chunks_exact(2) {
        if headers::is_allowed_client_header(&chunk[0].to_string()) {
            let header_name = match HeaderName::from_bytes(chunk[0].as_bytes()) {
                Err(_) => {
                    return res
                        .header(CONTENT_TYPE, CONTENT_TYPE_JSON)
                        .body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "Некорректный заголовок"))
                        .unwrap();
                }
                Ok(val) => val,
            };

            let header_value = match HeaderValue::from_bytes(chunk[1].as_bytes()) {
                Err(_) => {
                    return res
                        .header(CONTENT_TYPE, CONTENT_TYPE_JSON)
                        .body(
                            VLESS_ERROR_TEMPLATE
                                .replace("{{title}}", "Некорректное значение заголовка"),
                        )
                        .unwrap();
                }
                Ok(val) => val,
            };

            header_map.insert(header_name, header_value);
        }
    }

    let client = match Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
    {
        Err(_) => {
            return res
                .header(CONTENT_TYPE, CONTENT_TYPE_JSON)
                .body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "Ошибка настройки HTTP-клиента"))
                .unwrap();
        }
        Ok(client) => client,
    };

    let response = match client.get(url).headers(header_map).send().await {
        Err(_) => {
            return res
                .header(CONTENT_TYPE, CONTENT_TYPE_JSON)
                .body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "Ошибка отправки запроса"))
                .unwrap();
        }
        Ok(val) => val,
    };

    if let Some(headers) = res.headers_mut() {
        for (name, value) in response.headers() {
            if headers::is_allowed_subscription_header(&name.to_string()) {
                headers.append(name, value.clone());
            }
        }
    }

    let text = match response.text().await {
        Err(_) => {
            return res
                .header(CONTENT_TYPE, CONTENT_TYPE_JSON)
                .body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "Ошибка получения тела ответа"))
                .unwrap();
        }
        Ok(text) => text,
    };

    return res.body(text).unwrap();
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
        Err(_) => {
            return res
                .body(VLESS_ERROR_TEMPLATE.replace("{{title}}", "Ошибка сериализации"))
                .unwrap();
        }
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
