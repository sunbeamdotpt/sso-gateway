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
            client: Client::new(),
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
        let url = self.admin_url.join(&format!("admin/clients/{id}"))?;
        debug!(%url, "fetching hydra oauth2 client");
        self.send_json(Method::GET, url, None).await
    }

    /// Delete an OAuth 2.0 / OIDC client by its Ory global id.
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn delete_oauth2_client(&self, id: &str) -> Result<(), OryClientError> {
        let url = self.admin_url.join(&format!("admin/clients/{id}"))?;
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
        let url = self.admin_url.join(&format!("admin/clients/{id}"))?;
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
        let url = self.admin_url.join("oauth2/introspect")?;
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
        handle_response(response).await
    }

    /// Exchange credentials or a code for tokens at Hydra's public `/oauth2/token` endpoint.
    #[instrument(skip(self, form))]
    pub async fn token(&self, form: Vec<(String, String)>) -> Result<Value, OryClientError> {
        let url = self
            .public_url
            .join("oauth2/token")
            .map_err(OryClientError::Url)?;
        debug!(%url, "exchanging token");
        let response = self
            .client
            .post(url)
            .form(&form)
            .header("accept", "application/json")
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Call Hydra's public `/oauth2/userinfo` endpoint.
    #[instrument(skip(self))]
    pub async fn userinfo(&self, token: &str) -> Result<Value, OryClientError> {
        let url = self
            .public_url
            .join("oauth2/userinfo")
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
    use std::collections::HashMap;

    use axum::{
        Json, Router,
        extract::Form,
        routing::{get, post},
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
            .route("/oauth2/introspect", post(introspect))
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
}
