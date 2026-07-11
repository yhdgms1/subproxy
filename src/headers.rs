pub fn is_allowed_client_header(name: &str) -> bool {
    name.to_ascii_lowercase() == "user-agent" || name.starts_with("x-")
}

const SUBSCRIPTION_HEADERS_WHITELIST: [&str; 9] = [
    "subscription-userinfo",
    "profile-update-interval",
    "profile-title",
    "profile-web-page-url",
    "support-url",
    "announce",
    "announce-url",
    "content-type",
    "content-length",
];

/// Основные заголовки перенаправляются, остальные наверное нет смысла разрешать
pub fn is_allowed_subscription_header(name: &str) -> bool {
    SUBSCRIPTION_HEADERS_WHITELIST.contains(&name.to_ascii_lowercase().as_str())
}

const X_HEADERS_BLACKLIST: [&str; 5] = [
    "x-real-ip",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-port",
];

pub fn is_allowed_whoami_header(name: &str) -> bool {
    if name == "user-agent" {
        return true;
    }

    name.starts_with("x-") && !X_HEADERS_BLACKLIST.contains(&name)
}
