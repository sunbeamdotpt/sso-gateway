use reqwest::{Client, Method, Url};
use serde_json::Value;
use tracing::{debug, instrument};

use crate::error::OryClientError;

/// Internal client for Ory Hydra (admin and public endpoints).
#[derive(Debug, Clone)]
pub struct HydraClient {
    client: Client,
    admin_url: Url,
    #[allow(dead_code)]
    public_url: Url,
}

impl HydraClient {
    /// Create a new Hydra client.
    pub fn new(admin_url: &str, public_url: &str) -> Result<Self, OryClientError> {
        Ok(Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .connect_timeout(std::time::Duration::from_secs(5))
                // Hydra's authorization endpoint returns HTTP redirects that the
                // gateway must proxy to the caller. Never follow them internally.
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            admin_url: parse_base_url(admin_url)?,
            public_url: parse_base_url(public_url)?,
        })
    }

    /// Create an OAuth 2.0 / OIDC client.
    #[instrument(skip(self, payload), fields(admin_url = %self.admin_url))]
    pub async fn create_oauth2_client(&self, payload: Value) -> Result<Value, OryClientError> {
        let url = self.admin_url.join("admin/clients")?;
        debug!(%url, "creating hydra oauth2 client");
        self.send_json(Method::POST, url, Some(payload)).await
    }

    /// Get an OAuth 2.0 / OIDC client by its Ory global id.
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn get_oauth2_client(&self, id: &str) -> Result<Value, OryClientError> {
        let url = self
            .admin_url
            .join(&format!("admin/clients/{}", urlencoding::encode(id)))?;
        debug!(%url, "fetching hydra oauth2 client");
        self.send_json(Method::GET, url, None).await
    }

    /// Delete an OAuth 2.0 / OIDC client by its Ory global id.
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn delete_oauth2_client(&self, id: &str) -> Result<(), OryClientError> {
        let url = self
            .admin_url
            .join(&format!("admin/clients/{}", urlencoding::encode(id)))?;
        debug!(%url, "deleting hydra oauth2 client");
        self.send_empty(Method::DELETE, url).await
    }

    /// Update an OAuth 2.0 / OIDC client by its Ory global id.
    #[instrument(skip(self, payload), fields(admin_url = %self.admin_url))]
    pub async fn update_oauth2_client(
        &self,
        id: &str,
        payload: Value,
    ) -> Result<Value, OryClientError> {
        let url = self
            .admin_url
            .join(&format!("admin/clients/{}", urlencoding::encode(id)))?;
        debug!(%url, "updating hydra oauth2 client");
        self.send_json(Method::PUT, url, Some(payload)).await
    }

    /// Rotate an OAuth 2.0 / OIDC client's secret.
    ///
    /// Hydra returns the new secret only when `client_secret` is provided in a
    /// full `PUT /admin/clients/{id}` update, so we fetch the current client,
    /// inject a generated secret, and update it.
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn rotate_client_secret(&self, id: &str) -> Result<Value, OryClientError> {
        let mut client = self.get_oauth2_client(id).await?;
        let new_secret: String = rand::distributions::Distribution::sample_iter(
            rand::distributions::Alphanumeric,
            &mut rand::thread_rng(),
        )
        .take(32)
        .map(char::from)
        .collect();
        client["client_secret"] = serde_json::Value::String(new_secret);
        self.update_oauth2_client(id, client).await
    }

    /// Introspect an access or refresh token (admin endpoint).
    #[instrument(skip(self, token), fields(admin_url = %self.admin_url))]
    pub async fn introspect_token(&self, token: &str) -> Result<Value, OryClientError> {
        let url = self.admin_url.join("admin/oauth2/introspect")?;
        debug!(%url, "introspecting token");
        let form = [("token", token)];
        let response = self
            .client
            .post(url)
            .header("accept", "application/json")
            .form(&form)
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Fetch a login request by challenge.
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn get_login_request(&self, challenge: &str) -> Result<Value, OryClientError> {
        let url = self
            .admin_url
            .join("admin/oauth2/auth/requests/login")
            .map_err(OryClientError::Url)?;
        debug!(%url, "fetching login request");
        let response = self
            .client
            .get(url)
            .query(&[("login_challenge", challenge)])
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Accept a login request.
    #[instrument(skip(self, body), fields(admin_url = %self.admin_url))]
    pub async fn accept_login_request(
        &self,
        challenge: &str,
        body: Value,
    ) -> Result<Value, OryClientError> {
        let url = self
            .admin_url
            .join("admin/oauth2/auth/requests/login/accept")
            .map_err(OryClientError::Url)?;
        debug!(%url, "accepting login request");
        let response = self
            .client
            .put(url)
            .query(&[("login_challenge", challenge)])
            .json(&body)
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Reject a login request.
    #[instrument(skip(self, body), fields(admin_url = %self.admin_url))]
    pub async fn reject_login_request(
        &self,
        challenge: &str,
        body: Value,
    ) -> Result<Value, OryClientError> {
        let url = self
            .admin_url
            .join("admin/oauth2/auth/requests/login/reject")
            .map_err(OryClientError::Url)?;
        debug!(%url, "rejecting login request");
        let response = self
            .client
            .put(url)
            .query(&[("login_challenge", challenge)])
            .json(&body)
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Fetch a consent request by challenge.
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn get_consent_request(&self, challenge: &str) -> Result<Value, OryClientError> {
        let url = self
            .admin_url
            .join("admin/oauth2/auth/requests/consent")
            .map_err(OryClientError::Url)?;
        debug!(%url, "fetching consent request");
        let response = self
            .client
            .get(url)
            .query(&[("consent_challenge", challenge)])
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Accept a consent request.
    #[instrument(skip(self, body), fields(admin_url = %self.admin_url))]
    pub async fn accept_consent_request(
        &self,
        challenge: &str,
        body: Value,
    ) -> Result<Value, OryClientError> {
        let url = self
            .admin_url
            .join("admin/oauth2/auth/requests/consent/accept")
            .map_err(OryClientError::Url)?;
        debug!(%url, "accepting consent request");
        let response = self
            .client
            .put(url)
            .query(&[("consent_challenge", challenge)])
            .json(&body)
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Reject a consent request.
    #[instrument(skip(self, body), fields(admin_url = %self.admin_url))]
    pub async fn reject_consent_request(
        &self,
        challenge: &str,
        body: Value,
    ) -> Result<Value, OryClientError> {
        let url = self
            .admin_url
            .join("admin/oauth2/auth/requests/consent/reject")
            .map_err(OryClientError::Url)?;
        debug!(%url, "rejecting consent request");
        let response = self
            .client
            .put(url)
            .query(&[("consent_challenge", challenge)])
            .json(&body)
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Fetch a logout request by challenge.
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn get_logout_request(&self, challenge: &str) -> Result<Value, OryClientError> {
        let url = self
            .admin_url
            .join("admin/oauth2/auth/requests/logout")
            .map_err(OryClientError::Url)?;
        debug!(%url, "fetching logout request");
        let response = self
            .client
            .get(url)
            .query(&[("logout_challenge", challenge)])
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Accept a logout request.
    #[instrument(skip(self, body), fields(admin_url = %self.admin_url))]
    pub async fn accept_logout_request(
        &self,
        challenge: &str,
        body: Value,
    ) -> Result<Value, OryClientError> {
        let url = self
            .admin_url
            .join("admin/oauth2/auth/requests/logout/accept")
            .map_err(OryClientError::Url)?;
        debug!(%url, "accepting logout request");
        let response = self
            .client
            .put(url)
            .query(&[("logout_challenge", challenge)])
            .json(&body)
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Reject a logout request.
    #[instrument(skip(self, body), fields(admin_url = %self.admin_url))]
    pub async fn reject_logout_request(
        &self,
        challenge: &str,
        body: Value,
    ) -> Result<Value, OryClientError> {
        let url = self
            .admin_url
            .join("admin/oauth2/auth/requests/logout/reject")
            .map_err(OryClientError::Url)?;
        debug!(%url, "rejecting logout request");
        let response = self
            .client
            .put(url)
            .query(&[("logout_challenge", challenge)])
            .json(&body)
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Proxy an authorization request to Hydra's public `/oauth2/auth` endpoint.
    #[instrument(skip(self))]
    pub async fn authorize(&self, query: Vec<(String, String)>) -> Result<Value, OryClientError> {
        let url = self
            .public_url
            .join("oauth2/auth")
            .map_err(OryClientError::Url)?;
        debug!(%url, "proxying authorize request");
        let response = self
            .client
            .get(url)
            .query(&query)
            .header("accept", "application/json")
            .send()
            .await
            .map_err(OryClientError::Http)?;

        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|h| h.to_str().ok())
                .map(String::from)
                .unwrap_or_default();
            return Err(OryClientError::Redirect { location });
        }

        handle_response(response).await
    }

    /// Exchange credentials or a code for tokens at Hydra's public `/oauth2/token` endpoint.
    ///
    /// When `client_credentials` is provided, the client id and secret are sent
    /// using HTTP Basic authentication (the method required by
    /// `client_secret_basic` clients). Otherwise the credentials must be present
    /// in the form body (for `client_secret_post` clients).
    #[instrument(skip(self, form))]
    pub async fn token(
        &self,
        form: Vec<(String, String)>,
        client_credentials: Option<(&str, &str)>,
    ) -> Result<Value, OryClientError> {
        let url = self
            .public_url
            .join("oauth2/token")
            .map_err(OryClientError::Url)?;
        debug!(%url, "exchanging token");
        let mut request = self
            .client
            .post(url)
            .form(&form)
            .header("accept", "application/json");
        if let Some((client_id, client_secret)) = client_credentials {
            request = request.basic_auth(client_id, Some(client_secret));
        }
        let response = request.send().await.map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Call Hydra's public `/userinfo` endpoint.
    #[instrument(skip(self))]
    pub async fn userinfo(&self, token: &str) -> Result<Value, OryClientError> {
        let url = self
            .public_url
            .join("userinfo")
            .map_err(OryClientError::Url)?;
        debug!(%url, "fetching userinfo");
        let response = self
            .client
            .get(url)
            .bearer_auth(token)
            .header("accept", "application/json")
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Return the configured public base URL.
    pub fn public_url(&self) -> &Url {
        &self.public_url
    }

    /// Perform an arbitrary GET against a Hydra endpoint and parse JSON.
    #[instrument(skip(self))]
    pub async fn get_json(&self, url: Url) -> Result<Value, OryClientError> {
        let response = self
            .client
            .get(url)
            .header("accept", "application/json")
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Proxy a device-authorization request to Hydra's public
    /// `/oauth2/device/{path}` endpoint.
    #[instrument(skip(self, form))]
    pub async fn device(
        &self,
        path: &str,
        form: Vec<(String, String)>,
        client_credentials: Option<(&str, &str)>,
    ) -> Result<Value, OryClientError> {
        let url = self
            .public_url
            .join(&format!("oauth2/device/{}", urlencoding::encode(path)))
            .map_err(OryClientError::Url)?;
        debug!(%url, "proxying device request");
        let mut request = self
            .client
            .post(url)
            .form(&form)
            .header("accept", "application/json");
        if let Some((client_id, client_secret)) = client_credentials {
            request = request.basic_auth(client_id, Some(client_secret));
        }
        let response = request.send().await.map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Revoke a token at Hydra's public `/oauth2/revoke` endpoint.
    #[instrument(skip(self, form))]
    pub async fn revoke(&self, form: Vec<(String, String)>) -> Result<(), OryClientError> {
        let url = self
            .public_url
            .join("oauth2/revoke")
            .map_err(OryClientError::Url)?;
        debug!(%url, "revoking token");
        let response = self
            .client
            .post(url)
            .form(&form)
            .send()
            .await
            .map_err(OryClientError::Http)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ory_error(response).await)
        }
    }

    async fn send_json(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
    ) -> Result<Value, OryClientError> {
        let mut request = self
            .client
            .request(method, url)
            .header("accept", "application/json");
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    async fn send_empty(&self, method: Method, url: Url) -> Result<(), OryClientError> {
        let response = self
            .client
            .request(method, url)
            .send()
            .await
            .map_err(OryClientError::Http)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ory_error(response).await)
        }
    }
}

fn parse_base_url(url: &str) -> Result<Url, OryClientError> {
    let mut url = Url::parse(url).map_err(|e| OryClientError::InvalidResponse(e.to_string()))?;
    if !url.path().ends_with('/')
        && let Ok(mut path) = url.path_segments_mut()
    {
        path.push("");
    }
    Ok(url)
}

async fn handle_response(response: reqwest::Response) -> Result<Value, OryClientError> {
    if response.status().is_success() {
        response.json().await.map_err(OryClientError::Http)
    } else {
        Err(ory_error(response).await)
    }
}

async fn ory_error(response: reqwest::Response) -> OryClientError {
    let status = response.status().as_u16();
    let message = response
        .text()
        .await
        .unwrap_or_else(|_| "<unreadable body>".to_string());
    OryClientError::Ory { status, message }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    use axum::{
        Json, Router,
        extract::{Form, Query, State},
        routing::{delete, get, post, put},
    };
    use serde_json::json;

    use super::*;

    fn app() -> Router {
        Router::new()
            .route("/admin/clients", post(create_client))
            .route(
                "/admin/clients/{id}",
                get(get_client).put(update_client).delete(delete_client),
            )
            .route("/admin/oauth2/introspect", post(introspect))
            .route("/admin/oauth2/auth/requests/login", get(get_login_request))
            .route(
                "/admin/oauth2/auth/requests/login/accept",
                put(accept_login_request),
            )
            .route(
                "/admin/oauth2/auth/requests/login/reject",
                put(reject_login_request),
            )
            .route(
                "/admin/oauth2/auth/requests/consent",
                get(get_consent_request),
            )
            .route(
                "/admin/oauth2/auth/requests/consent/accept",
                put(accept_consent_request),
            )
            .route(
                "/admin/oauth2/auth/requests/consent/reject",
                put(reject_consent_request),
            )
            .route(
                "/admin/oauth2/auth/requests/logout",
                get(get_logout_request),
            )
            .route(
                "/admin/oauth2/auth/requests/logout/accept",
                put(accept_logout_request),
            )
            .route(
                "/admin/oauth2/auth/requests/logout/reject",
                put(reject_logout_request),
            )
            .route("/oauth2/auth", get(authorize))
            .route("/oauth2/token", post(token))
            .route("/oauth2/device/{*path}", post(device))
            .route("/userinfo", get(userinfo))
            .route("/oauth2/revoke", post(revoke))
            .route("/proxy-json", get(proxy_json))
    }

    async fn create_client(Json(body): Json<Value>) -> Json<Value> {
        Json(json!({
            "client_id": "client-1",
            "client_name": body.get("client_name").cloned().unwrap_or_default(),
        }))
    }

    async fn get_client(axum::extract::Path(id): axum::extract::Path<String>) -> Json<Value> {
        Json(json!({ "client_id": id, "client_name": "app" }))
    }

    async fn update_client(
        axum::extract::Path(id): axum::extract::Path<String>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        Json(json!({
            "client_id": id,
            "client_name": body.get("client_name").cloned().unwrap_or_default(),
            "client_secret": body.get("client_secret").cloned().unwrap_or_default(),
        }))
    }

    async fn delete_client() -> axum::http::StatusCode {
        axum::http::StatusCode::NO_CONTENT
    }

    async fn introspect(Form(form): Form<HashMap<String, String>>) -> Json<Value> {
        Json(json!({
            "active": true,
            "sub": form.get("token").cloned().unwrap_or_default(),
        }))
    }

    async fn introspect_admin_path(
        State(hit): State<Arc<AtomicBool>>,
        Form(form): Form<HashMap<String, String>>,
    ) -> Json<Value> {
        hit.store(true, Ordering::SeqCst);
        Json(json!({
            "active": true,
            "sub": form.get("token").cloned().unwrap_or_default(),
        }))
    }

    async fn introspect_public_path(State(hit): State<Arc<AtomicBool>>) -> Json<Value> {
        hit.store(true, Ordering::SeqCst);
        Json(json!({ "active": false }))
    }

    async fn get_login_request(Query(params): Query<HashMap<String, String>>) -> Json<Value> {
        Json(json!({
            "challenge": params.get("login_challenge").cloned().unwrap_or_default(),
            "subject": "subject-1",
            "client": { "client_id": "client-1" }
        }))
    }

    async fn accept_login_request(
        Query(params): Query<HashMap<String, String>>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        Json(json!({
            "challenge": params.get("login_challenge").cloned().unwrap_or_default(),
            "redirect_to": "http://redirect",
            "body": body
        }))
    }

    async fn reject_login_request(
        Query(params): Query<HashMap<String, String>>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        Json(json!({
            "challenge": params.get("login_challenge").cloned().unwrap_or_default(),
            "redirect_to": "http://redirect",
            "body": body
        }))
    }

    async fn get_consent_request(Query(params): Query<HashMap<String, String>>) -> Json<Value> {
        Json(json!({
            "challenge": params.get("consent_challenge").cloned().unwrap_or_default(),
            "subject": "subject-1",
            "client": { "client_id": "client-1" }
        }))
    }

    async fn accept_consent_request(
        Query(params): Query<HashMap<String, String>>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        Json(json!({
            "challenge": params.get("consent_challenge").cloned().unwrap_or_default(),
            "redirect_to": "http://redirect",
            "body": body
        }))
    }

    async fn reject_consent_request(
        Query(params): Query<HashMap<String, String>>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        Json(json!({
            "challenge": params.get("consent_challenge").cloned().unwrap_or_default(),
            "redirect_to": "http://redirect",
            "body": body
        }))
    }

    async fn get_logout_request(Query(params): Query<HashMap<String, String>>) -> Json<Value> {
        Json(json!({
            "challenge": params.get("logout_challenge").cloned().unwrap_or_default(),
            "subject": "subject-1",
            "client": { "client_id": "client-1" }
        }))
    }

    async fn accept_logout_request(
        Query(params): Query<HashMap<String, String>>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        Json(json!({
            "challenge": params.get("logout_challenge").cloned().unwrap_or_default(),
            "redirect_to": "http://redirect",
            "body": body
        }))
    }

    async fn reject_logout_request(
        Query(params): Query<HashMap<String, String>>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        Json(json!({
            "challenge": params.get("logout_challenge").cloned().unwrap_or_default(),
            "redirect_to": "http://redirect",
            "body": body
        }))
    }

    async fn authorize(Query(params): Query<HashMap<String, String>>) -> Json<Value> {
        Json(json!({
            "redirect_to": params.get("redirect_uri").cloned().unwrap_or_default(),
            "state": params.get("state").cloned().unwrap_or_default(),
        }))
    }

    async fn token(Form(form): Form<HashMap<String, String>>) -> Json<Value> {
        Json(json!({
            "access_token": form.get("code").cloned().unwrap_or_default(),
            "token_type": "Bearer",
        }))
    }

    async fn device(
        axum::extract::Path(path): axum::extract::Path<String>,
        Form(form): Form<HashMap<String, String>>,
    ) -> Json<Value> {
        if path == "auth" {
            Json(json!({
                "device_code": form.get("client_id").cloned().unwrap_or_default(),
                "user_code": "USER-CODE",
                "verification_uri": "https://gateway.example.com/device",
                "expires_in": 600,
                "interval": 5,
            }))
        } else {
            Json(json!({
                "access_token": format!("token-for-{path}"),
                "token_type": "Bearer",
            }))
        }
    }

    async fn userinfo(headers: axum::http::HeaderMap) -> Json<Value> {
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        Json(json!({ "sub": token.strip_prefix("Bearer ").unwrap_or("") }))
    }

    async fn revoke() -> axum::http::StatusCode {
        axum::http::StatusCode::NO_CONTENT
    }

    async fn proxy_json() -> Json<Value> {
        Json(json!({ "proxied": true }))
    }

    async fn error_handler() -> (axum::http::StatusCode, &'static str) {
        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "error")
    }

    async fn start_server() -> (tokio::task::JoinHandle<()>, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app()).await.unwrap();
        });
        (handle, format!("http://{addr}"))
    }

    #[tokio::test]
    async fn create_oauth2_client_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let resp = client
            .create_oauth2_client(json!({"client_name": "app"}))
            .await
            .unwrap();
        assert_eq!(resp["client_id"], "client-1");
        assert_eq!(resp["client_name"], "app");
    }

    #[tokio::test]
    async fn get_oauth2_client_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let resp = client.get_oauth2_client("client-1").await.unwrap();
        assert_eq!(resp["client_id"], "client-1");
        assert_eq!(resp["client_name"], "app");
    }

    #[tokio::test]
    async fn update_oauth2_client_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let resp = client
            .update_oauth2_client("client-1", json!({"client_name": "updated"}))
            .await
            .unwrap();
        assert_eq!(resp["client_id"], "client-1");
        assert_eq!(resp["client_name"], "updated");
    }

    #[tokio::test]
    async fn rotate_client_secret_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let resp = client.rotate_client_secret("client-1").await.unwrap();
        assert_eq!(resp["client_id"], "client-1");
        let secret = resp["client_secret"].as_str().expect("secret should exist");
        assert_eq!(secret.len(), 32);
    }

    #[tokio::test]
    async fn delete_oauth2_client_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        client.delete_oauth2_client("client-1").await.unwrap();
    }

    #[tokio::test]
    async fn introspect_token_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let resp = client.introspect_token("token-1").await.unwrap();
        assert_eq!(resp["active"], true);
        assert_eq!(resp["sub"], "token-1");
    }

    // Regression test for rc7: introspect_token must call Hydra's admin
    // introspection endpoint (`/admin/oauth2/introspect`), not the legacy
    // public path (`/oauth2/introspect`) on the admin port.
    #[tokio::test]
    async fn introspect_token_uses_admin_path() {
        let admin_hit = Arc::new(AtomicBool::new(false));
        let public_hit = Arc::new(AtomicBool::new(false));

        let app = Router::new()
            .route(
                "/admin/oauth2/introspect",
                post(introspect_admin_path).with_state(Arc::clone(&admin_hit)),
            )
            .route(
                "/oauth2/introspect",
                post(introspect_public_path).with_state(Arc::clone(&public_hit)),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client =
            HydraClient::new(&format!("http://{addr}"), &format!("http://{addr}")).unwrap();
        let resp = client.introspect_token("token-1").await.unwrap();

        assert_eq!(resp["active"], true);
        assert!(
            admin_hit.load(Ordering::SeqCst),
            "must hit /admin/oauth2/introspect"
        );
        assert!(
            !public_hit.load(Ordering::SeqCst),
            "must not hit legacy /oauth2/introspect on admin port"
        );
    }

    #[tokio::test]
    async fn ory_error_is_parsed() {
        let app = Router::new().route(
            "/admin/clients",
            post(|| async { (axum::http::StatusCode::BAD_REQUEST, "bad request") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            HydraClient::new(&format!("http://{addr}"), &format!("http://{addr}")).unwrap();
        let err = client.create_oauth2_client(json!({})).await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 400, .. }));
    }

    #[tokio::test]
    async fn get_logout_request_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let resp = client.get_logout_request("challenge-1").await.unwrap();
        assert_eq!(resp["challenge"], "challenge-1");
        assert_eq!(resp["subject"], "subject-1");
    }

    #[tokio::test]
    async fn accept_logout_request_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let resp = client
            .accept_logout_request("challenge-1", json!({}))
            .await
            .unwrap();
        assert_eq!(resp["redirect_to"], "http://redirect");
        assert_eq!(resp["challenge"], "challenge-1");
    }

    #[tokio::test]
    async fn reject_logout_request_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let resp = client
            .reject_logout_request("challenge-1", json!({ "error": "denied" }))
            .await
            .unwrap();
        assert_eq!(resp["redirect_to"], "http://redirect");
        assert_eq!(resp["body"]["error"], "denied");
    }

    #[tokio::test]
    async fn get_login_request_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let resp = client.get_login_request("challenge-1").await.unwrap();
        assert_eq!(resp["challenge"], "challenge-1");
        assert_eq!(resp["subject"], "subject-1");
    }

    #[tokio::test]
    async fn accept_login_request_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let resp = client
            .accept_login_request("challenge-1", json!({ "subject": "subject-1" }))
            .await
            .unwrap();
        assert_eq!(resp["redirect_to"], "http://redirect");
        assert_eq!(resp["challenge"], "challenge-1");
    }

    #[tokio::test]
    async fn reject_login_request_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let resp = client
            .reject_login_request("challenge-1", json!({ "error": "denied" }))
            .await
            .unwrap();
        assert_eq!(resp["body"]["error"], "denied");
    }

    #[tokio::test]
    async fn get_consent_request_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let resp = client.get_consent_request("challenge-1").await.unwrap();
        assert_eq!(resp["challenge"], "challenge-1");
    }

    #[tokio::test]
    async fn accept_consent_request_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let resp = client
            .accept_consent_request("challenge-1", json!({ "grant_scope": ["openid"] }))
            .await
            .unwrap();
        assert_eq!(resp["redirect_to"], "http://redirect");
    }

    #[tokio::test]
    async fn reject_consent_request_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let resp = client
            .reject_consent_request("challenge-1", json!({ "error": "denied" }))
            .await
            .unwrap();
        assert_eq!(resp["body"]["error"], "denied");
    }

    #[tokio::test]
    async fn authorize_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let resp = client
            .authorize(vec![
                ("redirect_uri".to_string(), "http://return".to_string()),
                ("state".to_string(), "state-1".to_string()),
            ])
            .await
            .unwrap();
        assert_eq!(resp["redirect_to"], "http://return");
        assert_eq!(resp["state"], "state-1");
    }

    #[tokio::test]
    async fn token_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let resp = client
            .token(vec![("code".to_string(), "code-1".to_string())], None)
            .await
            .unwrap();
        assert_eq!(resp["access_token"], "code-1");
        assert_eq!(resp["token_type"], "Bearer");
    }

    #[tokio::test]
    async fn userinfo_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let resp = client.userinfo("token-1").await.unwrap();
        assert_eq!(resp["sub"], "token-1");
    }

    #[tokio::test]
    async fn device_auth_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let resp = client
            .device(
                "auth",
                vec![
                    ("client_id".to_string(), "client-1".to_string()),
                    ("scope".to_string(), "openid".to_string()),
                ],
                None,
            )
            .await
            .unwrap();
        assert_eq!(resp["device_code"], "client-1");
        assert_eq!(resp["user_code"], "USER-CODE");
        assert_eq!(resp["expires_in"], 600);
        assert_eq!(resp["interval"], 5);
    }

    #[tokio::test]
    async fn device_token_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let resp = client
            .device(
                "token",
                vec![("grant_type".to_string(), "device_code".to_string())],
                None,
            )
            .await
            .unwrap();
        assert_eq!(resp["access_token"], "token-for-token");
        assert_eq!(resp["token_type"], "Bearer");
    }

    #[tokio::test]
    async fn revoke_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        client
            .revoke(vec![("token".to_string(), "token-1".to_string())])
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn get_json_round_trip() {
        let (_handle, url) = start_server().await;
        let client = HydraClient::new(&url, &url).unwrap();
        let url = client.public_url().join("proxy-json").unwrap();
        let resp = client.get_json(url).await.unwrap();
        assert_eq!(resp["proxied"], true);
    }

    #[tokio::test]
    async fn get_oauth2_client_error() {
        let app = Router::new().route("/admin/clients/{id}", get(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            HydraClient::new(&format!("http://{addr}"), &format!("http://{addr}")).unwrap();
        let err = client.get_oauth2_client("client-1").await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn delete_oauth2_client_error() {
        let app = Router::new().route("/admin/clients/{id}", delete(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            HydraClient::new(&format!("http://{addr}"), &format!("http://{addr}")).unwrap();
        let err = client.delete_oauth2_client("client-1").await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn update_oauth2_client_error() {
        let app = Router::new().route("/admin/clients/{id}", put(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            HydraClient::new(&format!("http://{addr}"), &format!("http://{addr}")).unwrap();
        let err = client
            .update_oauth2_client("client-1", json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn introspect_token_error() {
        let app = Router::new().route("/admin/oauth2/introspect", post(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            HydraClient::new(&format!("http://{addr}"), &format!("http://{addr}")).unwrap();
        let err = client.introspect_token("token-1").await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn get_login_request_error() {
        let app = Router::new().route("/admin/oauth2/auth/requests/login", get(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            HydraClient::new(&format!("http://{addr}"), &format!("http://{addr}")).unwrap();
        let err = client.get_login_request("challenge-1").await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn authorize_error() {
        let app = Router::new().route("/oauth2/auth", get(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            HydraClient::new(&format!("http://{addr}"), &format!("http://{addr}")).unwrap();
        let err = client.authorize(vec![]).await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn token_error() {
        let app = Router::new().route("/oauth2/token", post(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            HydraClient::new(&format!("http://{addr}"), &format!("http://{addr}")).unwrap();
        let err = client.token(vec![], None).await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn device_error() {
        let app = Router::new().route("/oauth2/device/{*path}", post(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            HydraClient::new(&format!("http://{addr}"), &format!("http://{addr}")).unwrap();
        let err = client.device("auth", vec![], None).await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn userinfo_error() {
        let app = Router::new().route("/userinfo", get(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            HydraClient::new(&format!("http://{addr}"), &format!("http://{addr}")).unwrap();
        let err = client.userinfo("token-1").await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn revoke_error() {
        let app = Router::new().route("/oauth2/revoke", post(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            HydraClient::new(&format!("http://{addr}"), &format!("http://{addr}")).unwrap();
        let err = client.revoke(vec![]).await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn get_json_error() {
        let app = Router::new().route("/proxy-json", get(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            HydraClient::new(&format!("http://{addr}"), &format!("http://{addr}")).unwrap();
        let url = client.public_url().join("proxy-json").unwrap();
        let err = client.get_json(url).await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn new_with_invalid_url() {
        let err = HydraClient::new("not-a-url", "http://example.com/").unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }
}
