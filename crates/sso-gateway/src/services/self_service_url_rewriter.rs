//! URL rewriting for Kratos self-service payloads.
//!
//! Kratos returns URLs that point at its own public endpoint and namespace
//! (`/self-service/**`, `/.well-known/ory/**`): form actions, AAL2 upgrade
//! redirects, logout chains, recovery and verification links, OIDC callback
//! targets. The gateway exposes its own branded browser surface instead —
//! browsers must never see an Ory path. This module rewrites those URLs to
//! the configured gateway paths ([`SelfServicePaths`]) and translates them
//! back on the way in.

use serde_json::Value;
use url::form_urlencoded;

use crate::config::SelfServicePaths;

/// Rewrite a URL that points at the Kratos public endpoint so it points at the
/// gateway instead, keeping the path unchanged. Non-Kratos URLs are returned
/// unchanged.
///
/// This is the host-only variant for caller- or application-owned URLs
/// (`return_to`, OAuth2 client URIs): the path is not the gateway's to
/// rebrand. Kratos-owned self-service routes go through
/// [`SelfServicePaths::rewrite_browser_url`], which also maps the path.
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

/// Rewrite any gateway-facing URL emitted by Kratos.
///
/// Browser-facing self-service routes are mapped onto the branded surface
/// ([`SelfServicePaths::rewrite_browser_url`]); everything else — flow
/// submission targets (`ui.action`), API paths — gets the host-only swap so
/// the Kratos endpoint never leaks. Caller- and application-owned URLs
/// (`return_to`, OAuth2 client URIs) must keep using [`rewrite_url`]: their
/// paths are not the gateway's to rebrand.
pub fn rewrite_gateway_facing_url(
    paths: &SelfServicePaths,
    url: &str,
    kratos_public_url: &str,
    gateway_url: &str,
) -> String {
    rewrite_url(
        &paths.rewrite_browser_url(url, kratos_public_url, gateway_url),
        kratos_public_url,
        gateway_url,
    )
}

/// Query parameters that carry nested URLs. Kratos embeds percent-encoded
/// URLs here (`return_to` on AAL2/re-auth redirects, `redirect_uri` inside
/// upstream IdP authorize URLs); the nested URL may itself point at a Kratos
/// self-service route and must be rewritten too.
const NESTED_URL_PARAMS: &[&str] = &["return_to", "redirect_uri"];

impl SelfServicePaths {
    /// The Kratos path → gateway path table, longest Kratos prefix first so
    /// `/self-service/logout/browser` wins over `/self-service/logout`.
    fn kratos_table(&self) -> [(&'static str, &str); 12] {
        [
            ("/self-service/login/browser", self.login.as_str()),
            ("/self-service/registration/browser", self.registration.as_str()),
            ("/self-service/settings/browser", self.settings.as_str()),
            ("/self-service/recovery/browser", self.recovery.as_str()),
            ("/self-service/verification/browser", self.verification.as_str()),
            ("/self-service/logout/browser", self.logout.as_str()),
            ("/self-service/recovery", self.recovery.as_str()),
            ("/self-service/verification", self.verification.as_str()),
            ("/self-service/logout", self.logout.as_str()),
            ("/self-service/errors", self.errors.as_str()),
            (
                "/self-service/methods/oidc/callback",
                self.oidc_callback.as_str(),
            ),
            ("/.well-known/ory/webauthn.js", self.webauthn_js.as_str()),
        ]
    }

    /// Match `path` against `prefix`: exact, or a path-segment boundary
    /// (`/{provider}` suffix on the OIDC callback).
    fn match_prefix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
        if path == prefix {
            return Some("");
        }
        path.strip_prefix(prefix)
            .filter(|suffix| suffix.starts_with('/'))
    }

    /// Rewrite a Kratos self-service path to the branded gateway path,
    /// preserving any suffix (e.g. the OIDC provider segment). Returns `None`
    /// when the path is not a browser-facing self-service route.
    pub fn gateway_path_for_kratos(&self, kratos_path: &str) -> Option<String> {
        self.kratos_table().into_iter().find_map(|(kratos, gateway)| {
            Self::match_prefix(kratos_path, kratos).map(|suffix| format!("{gateway}{suffix}"))
        })
    }

    /// Translate a branded gateway path back to the Kratos upstream path.
    /// Returns `None` when the path is not part of the branded surface.
    pub fn kratos_path_for_gateway(&self, gateway_path: &str) -> Option<String> {
        self.kratos_table().into_iter().find_map(|(kratos, gateway)| {
            Self::match_prefix(gateway_path, gateway).map(|suffix| format!("{kratos}{suffix}"))
        })
    }

    /// True when `path` belongs to the branded browser surface and must skip
    /// bearer-token authentication (it carries Kratos cookies instead).
    pub fn is_browser_path(&self, path: &str) -> bool {
        self.kratos_path_for_gateway(path).is_some()
    }

    /// Rewrite a Kratos-owned self-service URL to the branded gateway surface.
    ///
    /// The URL is rewritten when its path matches a browser-facing Kratos
    /// route and it points at either the Kratos public endpoint or the
    /// gateway itself (the gateway host appears when Kratos'
    /// `serve.public.base_url` is pointed at the gateway, e.g. for email
    /// links). Query parameters are preserved, with nested URLs in
    /// `return_to` / `redirect_uri` rewritten recursively. Anything else is
    /// returned unchanged.
    pub fn rewrite_browser_url(
        &self,
        url: &str,
        kratos_public_url: &str,
        gateway_url: &str,
    ) -> String {
        let kratos_prefix = kratos_public_url.trim_end_matches('/');
        let gateway_prefix = gateway_url.trim_end_matches('/');
        if !url.starts_with(kratos_prefix) && !url.starts_with(gateway_prefix) {
            return url.to_string();
        }
        let Ok(parsed) = reqwest::Url::parse(url) else {
            return url.to_string();
        };
        let Some(branded) = self.gateway_path_for_kratos(parsed.path()) else {
            return url.to_string();
        };
        let mut rewritten = format!("{gateway_prefix}{branded}");
        if let Some(query) = parsed.query() {
            rewritten.push('?');
            rewritten.push_str(&self.rewrite_nested_query(query, kratos_prefix, gateway_prefix));
        }
        if let Some(fragment) = parsed.fragment() {
            rewritten.push('#');
            rewritten.push_str(fragment);
        }
        rewritten
    }

    /// Rewrite nested URLs inside a raw query string, leaving every other
    /// pair byte-identical in order.
    fn rewrite_nested_query(&self, query: &str, kratos_prefix: &str, gateway_prefix: &str) -> String {
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form_urlencoded::parse(query.as_bytes()).map(|(key, value)| {
                if NESTED_URL_PARAMS.contains(&key.as_ref()) {
                    (
                        key,
                        self.rewrite_browser_url(&value, kratos_prefix, gateway_prefix).into(),
                    )
                } else {
                    (key, value)
                }
            }))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KRATOS: &str = "http://kratos.example.com";
    const GATEWAY: &str = "https://gateway.example.com";

    fn paths() -> SelfServicePaths {
        SelfServicePaths::default()
    }

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
        let rewritten = rewrite_url(
            url,
            "http://kratos.example.com",
            "https://gateway.example.com",
        );
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

    #[test]
    fn kratos_table_covers_every_browser_route() {
        let paths = paths();
        let cases = [
            ("/self-service/login/browser", "/identity/login"),
            ("/self-service/registration/browser", "/identity/registration"),
            ("/self-service/settings/browser", "/identity/settings"),
            ("/self-service/recovery/browser", "/identity/recovery"),
            ("/self-service/recovery", "/identity/recovery"),
            ("/self-service/verification/browser", "/identity/verification"),
            ("/self-service/verification", "/identity/verification"),
            ("/self-service/logout/browser", "/identity/logout"),
            ("/self-service/logout", "/identity/logout"),
            ("/self-service/errors", "/identity/errors"),
            ("/self-service/methods/oidc/callback", "/identity/oidc/callback"),
            (
                "/self-service/methods/oidc/callback/google",
                "/identity/oidc/callback/google",
            ),
            ("/.well-known/ory/webauthn.js", "/identity/webauthn.js"),
        ];
        for (kratos, expected) in cases {
            assert_eq!(
                paths.gateway_path_for_kratos(kratos).as_deref(),
                Some(expected),
                "kratos path {kratos}"
            );
            // The reverse translation picks the longest (browser-init) Kratos
            // route for doubly-mapped paths; assert consistency rather than
            // an exact source route (pinned in kratos_table_longest_prefix_wins).
            let reverse = paths
                .kratos_path_for_gateway(expected)
                .unwrap_or_else(|| panic!("gateway path {expected}"));
            assert_eq!(
                paths.gateway_path_for_kratos(&reverse).as_deref(),
                Some(expected),
                "round-trip via {reverse}"
            );
            assert!(paths.is_browser_path(expected), "{expected} is public");
        }
    }

    #[test]
    fn kratos_table_longest_prefix_wins() {
        let paths = paths();
        // `/self-service/logout/browser` must not be swallowed by
        // `/self-service/logout` (both map to the same branded path, but the
        // reverse translation must pick the browser route for init URLs).
        assert_eq!(
            paths.gateway_path_for_kratos("/self-service/logout/browser"),
            Some("/identity/logout".to_string())
        );
        // The reverse translation is deterministic: the branded logout path
        // maps to the first (longest) matching Kratos route.
        assert_eq!(
            paths.kratos_path_for_gateway("/identity/logout"),
            Some("/self-service/logout/browser".to_string())
        );
    }

    #[test]
    fn kratos_table_ignores_api_and_submit_routes() {
        let paths = paths();
        // API/JSON routes and flow submission endpoints are never
        // browser-navigated; they must not be rewritten or proxied.
        for path in [
            "/self-service/login",
            "/self-service/login/flows",
            "/self-service/settings",
            "/self-service/methods/oidc",
            "/sessions/whoami",
        ] {
            assert_eq!(paths.gateway_path_for_kratos(path), None, "{path}");
            assert!(!paths.is_browser_path(path), "{path}");
        }
    }

    #[test]
    fn rewrite_browser_url_maps_path_and_preserves_query() {
        let paths = paths();
        let rewritten = paths.rewrite_browser_url(
            "http://kratos.example.com/self-service/login/browser?aal=aal2&refresh=true",
            KRATOS,
            GATEWAY,
        );
        assert_eq!(
            rewritten,
            "https://gateway.example.com/identity/login?aal=aal2&refresh=true"
        );
    }

    #[test]
    fn rewrite_browser_url_rewrites_gateway_hosted_kratos_paths() {
        // When Kratos' base_url points at the gateway (email links), emitted
        // URLs carry the gateway host with Kratos paths; they still map.
        let paths = paths();
        let rewritten = paths.rewrite_browser_url(
            "https://gateway.example.com/self-service/recovery?token=t&flow=f",
            KRATOS,
            GATEWAY,
        );
        assert_eq!(
            rewritten,
            "https://gateway.example.com/identity/recovery?token=t&flow=f"
        );
    }

    #[test]
    fn rewrite_browser_url_rewrites_nested_return_to() {
        let paths = paths();
        let rewritten = paths.rewrite_browser_url(
            "http://kratos.example.com/self-service/login/browser?aal=aal2&return_to=http%3A%2F%2Fkratos.example.com%2Fself-service%2Fsettings%2Fbrowser%3Fflow%3D1",
            KRATOS,
            GATEWAY,
        );
        assert_eq!(
            rewritten,
            "https://gateway.example.com/identity/login?aal=aal2&return_to=https%3A%2F%2Fgateway.example.com%2Fidentity%2Fsettings%3Fflow%3D1"
        );
    }

    #[test]
    fn rewrite_browser_url_leaves_foreign_nested_urls_alone() {
        let paths = paths();
        let rewritten = paths.rewrite_browser_url(
            "http://kratos.example.com/self-service/login/browser?return_to=https%3A%2F%2Fui.example.com%2Fwelcome",
            KRATOS,
            GATEWAY,
        );
        assert_eq!(
            rewritten,
            "https://gateway.example.com/identity/login?return_to=https%3A%2F%2Fui.example.com%2Fwelcome"
        );
    }

    #[test]
    fn rewrite_browser_url_ignores_foreign_hosts_and_unmapped_paths() {
        let paths = paths();
        let foreign = "https://other.example.com/self-service/login/browser";
        assert_eq!(paths.rewrite_browser_url(foreign, KRATOS, GATEWAY), foreign);
        let unmapped = "http://kratos.example.com/self-service/login/flows?id=1";
        assert_eq!(paths.rewrite_browser_url(unmapped, KRATOS, GATEWAY), unmapped);
    }

    #[test]
    fn rewrite_browser_url_tolerates_unparseable_urls() {
        let paths = paths();
        let relative = "self-service/login/browser";
        assert_eq!(paths.rewrite_browser_url(relative, KRATOS, GATEWAY), relative);
    }

    #[test]
    fn rewrite_gateway_facing_url_brands_browser_routes_and_swaps_submit_hosts() {
        let paths = paths();
        // Browser init route: branded path.
        assert_eq!(
            rewrite_gateway_facing_url(
                &paths,
                "http://kratos.example.com/self-service/settings/browser?flow=1",
                KRATOS,
                GATEWAY,
            ),
            "https://gateway.example.com/identity/settings?flow=1"
        );
        // Submit target (`ui.action`): not a browser route, host-only swap.
        assert_eq!(
            rewrite_gateway_facing_url(
                &paths,
                "http://kratos.example.com/self-service/login?flow=1",
                KRATOS,
                GATEWAY,
            ),
            "https://gateway.example.com/self-service/login?flow=1"
        );
        // Foreign URL: untouched.
        let foreign = "https://other.example.com/self-service/login/browser";
        assert_eq!(
            rewrite_gateway_facing_url(&paths, foreign, KRATOS, GATEWAY),
            foreign
        );
    }

    #[test]
    fn configured_paths_drive_the_table() {
        let paths = SelfServicePaths {
            login: "/signin".to_string(),
            webauthn_js: "/assets/passkeys.js".to_string(),
            ..SelfServicePaths::default()
        };
        assert_eq!(
            paths.gateway_path_for_kratos("/self-service/login/browser"),
            Some("/signin".to_string())
        );
        assert_eq!(
            paths.kratos_path_for_gateway("/signin"),
            Some("/self-service/login/browser".to_string())
        );
        assert_eq!(
            paths.gateway_path_for_kratos("/.well-known/ory/webauthn.js"),
            Some("/assets/passkeys.js".to_string())
        );
        assert!(paths.is_browser_path("/signin"));
        assert!(!paths.is_browser_path("/identity/login"));
    }
}
