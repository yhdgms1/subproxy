use crate::{headers, ssrf};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode, header::CONTENT_TYPE};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use reqwest::redirect::Policy;
use reqwest::{Client, Url};
use std::time::Duration;

const VLESS_ERROR_TEMPLATE: &str = include_str!("./vless-templates/error.json");
const CONTENT_TYPE_JSON: &str = "application/json; charset=UTF-8";

pub struct Error(&'static str);

impl Error {
    pub fn new(title: &'static str) -> Self {
        Self(title)
    }

    pub fn title(&self) -> &'static str {
        self.0
    }
}

pub struct Subscription {
    pub body: String,
    pub headers: HeaderMap,
}

impl Subscription {
    pub fn into_response(self) -> Response<String> {
        let mut response = Response::builder().status(StatusCode::OK);

        if let Some(out) = response.headers_mut() {
            for (name, value) in &self.headers {
                out.append(name, value.clone());
            }
        }

        response.body(self.body).unwrap()
    }
}

pub fn error_response(title: &str) -> Response<String> {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, CONTENT_TYPE_JSON)
        .body(VLESS_ERROR_TEMPLATE.replace("{{title}}", title))
        .unwrap()
}

pub fn client() -> Client {
    Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

pub async fn load(
    client: &Client,
    host: &str,
    path: &str,
    headers_b64: &str,
) -> Result<Subscription, Error> {
    if headers_b64.len() > 2 * 1024 {
        return Err(Error::new("Размер заголовков слишком велик"));
    }

    let mut url = match Url::parse(&format!("https://{host}")) {
        Ok(url) => url,
        Err(_) => return Err(Error::new("Неверный адрес")),
    };

    url.set_path(path);

    let host_str = match url.host_str() {
        Some(host) => host.to_string(),
        None => return Err(Error::new("Некорректный хост")),
    };

    if !ssrf::is_host_safe(&host_str).await {
        return Err(Error::new("Хост запрещён"));
    }

    let headers = match URL_SAFE.decode(headers_b64) {
        Ok(headers) => headers,
        Err(_) => return Err(Error::new("Ошибка декодирования заголовков")),
    };

    let headers = match String::from_utf8(headers) {
        Ok(headers) => headers,
        Err(_) => return Err(Error::new("Ошибка конвертации заголовков")),
    };

    let headers: Vec<String> = match serde_json::from_str(&headers) {
        Ok(headers) => headers,
        Err(_) => return Err(Error::new("Ошибка парсинга заголовков")),
    };

    if headers.len() % 2 != 0 {
        return Err(Error::new("Нечётное количество заголовков"));
    }

    let mut header_map = HeaderMap::new();

    for chunk in headers.chunks_exact(2) {
        if !headers::is_allowed_client_header(&chunk[0]) {
            continue;
        }

        let header_name = match HeaderName::from_bytes(chunk[0].as_bytes()) {
            Ok(name) => name,
            Err(_) => return Err(Error::new("Некорректный заголовок")),
        };

        let header_value = match HeaderValue::from_bytes(chunk[1].as_bytes()) {
            Ok(value) => value,
            Err(_) => return Err(Error::new("Некорректное значение заголовка")),
        };

        header_map.insert(header_name, header_value);
    }

    let response = match client.get(url).headers(header_map).send().await {
        Ok(response) => response,
        Err(_) => return Err(Error::new("Ошибка отправки запроса")),
    };

    let mut headers = HeaderMap::new();

    for (name, value) in response.headers() {
        if headers::is_allowed_subscription_header(name.as_str()) {
            headers.append(name, value.clone());
        }
    }

    let body = match response.text().await {
        Ok(body) => body,
        Err(_) => return Err(Error::new("Ошибка получения тела ответа")),
    };

    Ok(Subscription { body, headers })
}
