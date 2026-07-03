//! URL rewriting for Kratos self-service payloads.
//!
//! Kratos returns URLs that point at the Kratos public endpoint (e.g. form
//! actions, recovery links, verification links). The gateway exposes its own
//! public self-service proxy so browsers never need to reach Kratos directly.
//! This module rewrites those URLs to use the gateway's public base URL.

use serde_json::Value;

/// Rewrite a URL that points at the Kratos public endpoint so it points at the
/// gateway instead. Non-Kratos URLs are returned unchanged.
pub fn rewrite_url(url: &str, kratos_public_url: &str, gateway_url: &str) -> String {
    let kratos_prefix = kratos_public_url.trim_end_matches('/');
    if let Some(suffix) = url.strip_prefix(kratos_prefix) {
        format!("{}{}", gateway_url.trim_end_matches('/'), suffix)
    } else {
        url.to_string()
    }
}

/// Recursively rewrite Kratos URLs inside a JSON value.
pub fn rewrite_json_urls(value: &mut Value, kratos_public_url: &str, gateway_url: &str) {
    match value {
        Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                rewrite_json_urls(v, kratos_public_url, gateway_url);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                rewrite_json_urls(v, kratos_public_url, gateway_url);
            }
        }
        Value::String(s) => {
            *s = rewrite_url(s, kratos_public_url, gateway_url);
        }
        _ => {}
    }
}

/// Rewrite a self-service URL path so it uses the gateway public base URL.
///
/// This is a convenience helper for callers that already know they have a
/// Kratos self-service path (e.g. `/self-service/recovery?token=...`).
pub fn rewrite_self_service_path(path: &str, gateway_url: &str) -> String {
    format!("{}{}", gateway_url.trim_end_matches('/'), path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rewrite_url_replaces_kratos_prefix() {
        let rewritten = rewrite_url(
            "http://kratos.example.com/self-service/recovery?token=abc",
            "http://kratos.example.com",
            "https://gateway.example.com",
        );
        assert_eq!(
            rewritten,
            "https://gateway.example.com/self-service/recovery?token=abc"
        );
    }

    #[test]
    fn rewrite_url_preserves_unrelated_urls() {
        let url = "https://other.example.com/self-service/recovery?token=abc";
        let rewritten = rewrite_url(url, "http://kratos.example.com", "https://gateway.example.com");
        assert_eq!(rewritten, url);
    }

    #[test]
    fn rewrite_url_handles_trailing_slashes() {
        let rewritten = rewrite_url(
            "http://kratos.example.com/self-service/login",
            "http://kratos.example.com/",
            "https://gateway.example.com/",
        );
        assert_eq!(rewritten, "https://gateway.example.com/self-service/login");
    }

    #[test]
    fn rewrite_json_urls_rewrites_nested_strings() {
        let mut value = json!({
            "action": "http://kratos.example.com/self-service/login?flow=1",
            "nested": {
                "link": "http://kratos.example.com/self-service/verification?token=t"
            },
            "items": [
                "http://kratos.example.com/.well-known/ory/webauthn.js"
            ]
        });
        rewrite_json_urls(
            &mut value,
            "http://kratos.example.com",
            "https://gateway.example.com",
        );
        assert_eq!(
            value["action"],
            "https://gateway.example.com/self-service/login?flow=1"
        );
        assert_eq!(
            value["nested"]["link"],
            "https://gateway.example.com/self-service/verification?token=t"
        );
        assert_eq!(
            value["items"][0],
            "https://gateway.example.com/.well-known/ory/webauthn.js"
        );
    }

    #[test]
    fn rewrite_self_service_path_prefixes_gateway_url() {
        let rewritten = rewrite_self_service_path(
            "/self-service/recovery?token=abc",
            "https://gateway.example.com",
        );
        assert_eq!(
            rewritten,
            "https://gateway.example.com/self-service/recovery?token=abc"
        );
    }
}
