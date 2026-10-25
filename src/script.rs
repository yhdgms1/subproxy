use crate::headers;
use crate::subscription::{Error, Subscription};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use rquickjs::context::intrinsic::{Eval, Json, Promise, RegExp, RegExpCompiler};
use rquickjs::{Context, Ctx, Function, Module, Object, Runtime, Value};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const SCRIPT_ENCODED_MAX: usize = 16 * 1024;
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(1);
const SCRIPT_MEMORY_LIMIT: usize = 8 * 1024 * 1024;

const TITLE_SCRIPT: &str = "Ошибка выполнения скрипта";
const TITLE_TIMEOUT: &str = "Превышено время выполнения скрипта";
const TITLE_MEMORY: &str = "Превышен лимит памяти скрипта";
const TITLE_EMPTY: &str = "Пустой ответ скрипта";

pub fn decode(encoded: &str) -> Result<String, Error> {
    if encoded.len() > SCRIPT_ENCODED_MAX {
        return Err(Error::new("Размер скрипта слишком велик"));
    }

    let bytes = match URL_SAFE.decode(encoded) {
        Ok(bytes) => bytes,
        Err(_) => return Err(Error::new("Ошибка декодирования скрипта")),
    };

    match String::from_utf8(bytes) {
        Ok(source) => Ok(source),
        Err(_) => Err(Error::new("Ошибка конвертации скрипта")),
    }
}

pub async fn run(source: String, subscription: Subscription) -> Result<Subscription, Error> {
    match tokio::task::spawn_blocking(move || run_blocking(source, subscription)).await {
        Ok(result) => result,
        Err(_) => Err(Error::new(TITLE_SCRIPT)),
    }
}

fn run_blocking(source: String, subscription: Subscription) -> Result<Subscription, Error> {
    let timed_out = Arc::new(AtomicBool::new(false));
    let runtime = match Runtime::new() {
        Ok(runtime) => runtime,
        Err(_) => return Err(Error::new(TITLE_SCRIPT)),
    };

    runtime.set_memory_limit(SCRIPT_MEMORY_LIMIT);

    let flag = Arc::clone(&timed_out);
    let started = Instant::now();

    runtime.set_interrupt_handler(Some(Box::new(move || {
        if started.elapsed() > SCRIPT_TIMEOUT {
            flag.store(true, Ordering::Relaxed);
            true
        } else {
            false
        }
    })));

    let context = match Context::custom::<(Eval, Promise, Json, RegExpCompiler, RegExp)>(&runtime) {
        Ok(context) => context,
        Err(_) => return Err(Error::new(TITLE_SCRIPT)),
    };

    context.with(|ctx| execute(&ctx, &source, subscription, &timed_out))
}

fn execute(
    ctx: &Ctx<'_>,
    source: &str,
    subscription: Subscription,
    timed_out: &AtomicBool,
) -> Result<Subscription, Error> {
    let pairs = collapsed_headers(&subscription.headers);
    let body_value = match ctx.json_parse(subscription.body.as_bytes().to_vec()) {
        Ok(value) => value,
        Err(err) => {
            if let Some(failure) = limit_failure(ctx, timed_out, err) {
                return Err(failure);
            }

            match rquickjs::String::from_str(ctx.clone(), &subscription.body) {
                Ok(value) => value.into_value(),
                Err(err) => return Err(fail(ctx, timed_out, err)),
            }
        }
    };

    let headers_obj = match Object::new(ctx.clone()) {
        Ok(object) => object,
        Err(err) => return Err(fail(ctx, timed_out, err)),
    };

    for (name, value) in &pairs {
        if let Err(err) = headers_obj.set(name.as_str(), value.as_str()) {
            return Err(fail(ctx, timed_out, err));
        }
    }

    let module = match Module::declare(ctx.clone(), b"script".to_vec(), source.as_bytes().to_vec())
    {
        Ok(module) => module,
        Err(err) => return Err(fail(ctx, timed_out, err)),
    };

    let (module, promise) = match module.eval() {
        Ok(evaluated) => evaluated,
        Err(err) => return Err(fail(ctx, timed_out, err)),
    };

    if let Err(err) = promise.finish::<()>() {
        return Err(fail(ctx, timed_out, err));
    }

    let handle: Function = match module.get("handle") {
        Ok(handle) => handle,
        Err(err) => return Err(fail(ctx, timed_out, err)),
    };

    let returned: Value = match handle.call((body_value, headers_obj)) {
        Ok(returned) => returned,
        Err(err) => return Err(fail(ctx, timed_out, err)),
    };

    let returned = if returned.is_promise() {
        let promise = returned.into_promise().unwrap();

        match promise.finish() {
            Ok(value) => value,
            Err(err) => return Err(fail(ctx, timed_out, err)),
        }
    } else {
        returned
    };

    let result = match plain_object(returned) {
        Some(object) => object,
        None => return Err(Error::new(TITLE_SCRIPT)),
    };

    let body: String = match result.get("body") {
        Ok(body) => body,
        Err(err) => return Err(fail(ctx, timed_out, err)),
    };

    if body.is_empty() {
        return Err(Error::new(TITLE_EMPTY));
    }

    let headers = match script_headers(ctx, &result, subscription.headers, timed_out) {
        Ok(headers) => headers,
        Err(err) => return Err(err),
    };

    Ok(Subscription { body, headers })
}

fn script_headers(
    ctx: &Ctx<'_>,
    result: &Object<'_>,
    upstream: HeaderMap,
    timed_out: &AtomicBool,
) -> Result<HeaderMap, Error> {
    let present = match result.contains_key("headers") {
        Ok(present) => present,
        Err(err) => return Err(fail(ctx, timed_out, err)),
    };

    if !present {
        return Ok(without_content_length(upstream));
    }

    let raw: Value = match result.get("headers") {
        Ok(raw) => raw,
        Err(err) => return Err(fail(ctx, timed_out, err)),
    };

    if raw.is_null() || raw.is_undefined() {
        return Ok(without_content_length(upstream));
    }

    let Some(object) = plain_object(raw) else {
        return Err(Error::new(TITLE_SCRIPT));
    };

    let mut headers = HeaderMap::new();

    for item in object.props::<String, String>() {
        let (name, value) = match item {
            Ok(item) => item,
            Err(err) => return Err(fail(ctx, timed_out, err)),
        };

        if name.eq_ignore_ascii_case("content-length") {
            continue;
        }

        if !headers::is_allowed_subscription_header(&name) {
            continue;
        }

        let header_name = match HeaderName::from_bytes(name.as_bytes()) {
            Ok(name) => name,
            Err(_) => return Err(Error::new("Некорректный заголовок")),
        };

        let header_value = match HeaderValue::from_bytes(value.as_bytes()) {
            Ok(value) => value,
            Err(_) => return Err(Error::new("Некорректное значение заголовка")),
        };

        headers.append(header_name, header_value);
    }

    Ok(headers)
}

fn plain_object(value: Value<'_>) -> Option<Object<'_>> {
    if value.is_array() || value.is_function() || value.is_promise() {
        return None;
    }

    value.into_object()
}

fn collapsed_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut names: Vec<String> = Vec::new();
    let mut values: Vec<String> = Vec::new();

    for (name, value) in headers {
        let Ok(value) = value.to_str() else {
            continue;
        };

        let name = name.as_str().to_ascii_lowercase();

        if let Some(index) = names.iter().position(|existing| existing == &name) {
            values[index].push_str(", ");
            values[index].push_str(value);
        } else {
            names.push(name);
            values.push(value.to_string());
        }
    }

    names.into_iter().zip(values).collect()
}

fn without_content_length(mut headers: HeaderMap) -> HeaderMap {
    while headers.remove(axum::http::header::CONTENT_LENGTH).is_some() {}

    headers
}

fn limit_failure(ctx: &Ctx<'_>, timed_out: &AtomicBool, err: rquickjs::Error) -> Option<Error> {
    if timed_out.load(Ordering::Relaxed) {
        ctx.catch();
        return Some(Error::new(TITLE_TIMEOUT));
    }

    if matches!(err, rquickjs::Error::WouldBlock) {
        return Some(Error::new(TITLE_TIMEOUT));
    }

    if matches!(err, rquickjs::Error::Exception) {
        let value = ctx.catch();

        if is_out_of_memory(&value) {
            return Some(Error::new(TITLE_MEMORY));
        }
    }

    None
}

fn fail(ctx: &Ctx<'_>, timed_out: &AtomicBool, err: rquickjs::Error) -> Error {
    limit_failure(ctx, timed_out, err).unwrap_or(Error::new(TITLE_SCRIPT))
}

fn is_out_of_memory(value: &Value<'_>) -> bool {
    let message = if let Some(text) = value.as_string() {
        text.to_string().unwrap_or_default()
    } else if let Some(object) = value.as_object() {
        object.get::<_, String>("message").unwrap_or_default()
    } else {
        String::new()
    };

    message.to_ascii_lowercase().contains("out of memory")
}
