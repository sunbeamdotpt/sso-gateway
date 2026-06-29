use reqwest::{Client, Method, Url};
use serde_json::Value;
use tracing::{debug, instrument};

use crate::error::OryClientError;

/// Internal client for Ory Kratos (admin and public endpoints).
#[derive(Debug, Clone)]
pub struct KratosClient {
    client: Client,
    admin_url: Url,
    public_url: Option<Url>,
}

impl KratosClient {
    /// Create a new Kratos admin client.
    pub fn new(admin_url: &str) -> Result<Self, OryClientError> {
        Ok(Self {
            client: Client::new(),
            admin_url: parse_base_url(admin_url)?,
            public_url: None,
        })
    }

    /// Create a client with both admin and public endpoints configured.
    pub fn new_with_public(admin_url: &str, public_url: &str) -> Result<Self, OryClientError> {
        Ok(Self {
            client: Client::new(),
            admin_url: parse_base_url(admin_url)?,
            public_url: Some(parse_base_url(public_url)?),
        })
    }

    /// Create an identity.
    #[instrument(skip(self, payload), fields(admin_url = %self.admin_url))]
    pub async fn create_identity(&self, payload: Value) -> Result<Value, OryClientError> {
        let url = self.admin_url.join("admin/identities")?;
        debug!(%url, "creating kratos identity");
        self.send_json(Method::POST, url, Some(payload)).await
    }

    /// Get an identity by its Ory global id.
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn get_identity(&self, id: &str) -> Result<Value, OryClientError> {
        let url = self.admin_url.join(&format!("admin/identities/{id}"))?;
        debug!(%url, "fetching kratos identity");
        self.send_json(Method::GET, url, None).await
    }

    /// Update an identity by its Ory global id.
    #[instrument(skip(self, payload), fields(admin_url = %self.admin_url))]
    pub async fn update_identity(&self, id: &str, payload: Value) -> Result<Value, OryClientError> {
        let url = self.admin_url.join(&format!("admin/identities/{id}"))?;
        debug!(%url, "updating kratos identity");
        self.send_json(Method::PUT, url, Some(payload)).await
    }

    /// Delete an identity by its Ory global id.
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn delete_identity(&self, id: &str) -> Result<(), OryClientError> {
        let url = self.admin_url.join(&format!("admin/identities/{id}"))?;
        debug!(%url, "deleting kratos identity");
        self.send_empty(Method::DELETE, url).await
    }

    /// Get the active identity schema.
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn get_identity_schema(&self, id: &str) -> Result<Value, OryClientError> {
        let url = self.admin_url.join(&format!("schemas/{id}"))?;
        debug!(%url, "fetching kratos identity schema");
        self.send_json(Method::GET, url, None).await
    }

    /// Get a session by its Ory global id.
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn admin_get_session(&self, id: &str) -> Result<Value, OryClientError> {
        let url = self.admin_url.join(&format!("admin/sessions/{id}"))?;
        debug!(%url, "fetching kratos session");
        self.send_json(Method::GET, url, None).await
    }

    /// List sessions for an identity.
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn list_sessions_by_identity(
        &self,
        identity_id: &str,
    ) -> Result<Value, OryClientError> {
        let url = self.admin_url.join("admin/sessions")?;
        debug!(%url, %identity_id, "listing kratos sessions");
        let response = self
            .client
            .get(url)
            .query(&[("identity_id", identity_id)])
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Delete a session by its Ory global id.
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn delete_session(&self, id: &str) -> Result<(), OryClientError> {
        let url = self.admin_url.join(&format!("admin/sessions/{id}"))?;
        debug!(%url, "deleting kratos session");
        self.send_empty(Method::DELETE, url).await
    }

    /// Validate a session token via the public whoami endpoint.
    #[instrument(skip(self))]
    pub async fn whoami(&self, session_token: &str) -> Result<Value, OryClientError> {
        let public_url = self
            .public_url
            .as_ref()
            .ok_or_else(|| OryClientError::InvalidResponse("kratos public url not set".into()))?;
        let url = public_url.join("sessions/whoami")?;
        debug!(%url, "validating kratos session");
        let response = self
            .client
            .get(url)
            .header("X-Session-Token", session_token)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Create a self-service login flow via the public API.
    #[instrument(skip(self))]
    pub async fn create_login_flow(
        &self,
        return_to: Option<&str>,
    ) -> Result<Value, OryClientError> {
        let public_url = self
            .public_url
            .as_ref()
            .ok_or_else(|| OryClientError::InvalidResponse("kratos public url not set".into()))?;
        let url = public_url.join("self-service/login/api")?;
        let mut request = self.client.get(url).header("accept", "application/json");
        if let Some(return_to) = return_to {
            request = request.query(&[("return_to", return_to)]);
        }
        let response = request.send().await.map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Create a self-service registration flow via the public API.
    #[instrument(skip(self))]
    pub async fn create_registration_flow(
        &self,
        return_to: Option<&str>,
    ) -> Result<Value, OryClientError> {
        let public_url = self
            .public_url
            .as_ref()
            .ok_or_else(|| OryClientError::InvalidResponse("kratos public url not set".into()))?;
        let url = public_url.join("self-service/registration/api")?;
        let mut request = self.client.get(url).header("accept", "application/json");
        if let Some(return_to) = return_to {
            request = request.query(&[("return_to", return_to)]);
        }
        let response = request.send().await.map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Validate a session from a browser cookie or explicit token via the public whoami endpoint.
    #[instrument(skip(self, cookie, token))]
    pub async fn to_session(
        &self,
        cookie: Option<&str>,
        token: Option<&str>,
    ) -> Result<Value, OryClientError> {
        let public_url = self
            .public_url
            .as_ref()
            .ok_or_else(|| OryClientError::InvalidResponse("kratos public url not set".into()))?;
        let url = public_url.join("sessions/whoami")?;
        let mut request = self.client.get(url).header("accept", "application/json");
        if let Some(token) = token {
            request = request.header("X-Session-Token", token);
        }
        if let Some(cookie) = cookie {
            request = request.header("Cookie", cookie);
        }
        let response = request.send().await.map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Get an existing self-service login flow by id.
    #[instrument(skip(self, cookie))]
    pub async fn get_login_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.get_flow("login", id, cookie).await
    }

    /// Get an existing self-service registration flow by id.
    #[instrument(skip(self, cookie))]
    pub async fn get_registration_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.get_flow("registration", id, cookie).await
    }

    /// Get an existing self-service settings flow by id.
    #[instrument(skip(self, cookie))]
    pub async fn get_settings_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.get_flow("settings", id, cookie).await
    }

    /// Get an existing self-service recovery flow by id.
    #[instrument(skip(self, cookie))]
    pub async fn get_recovery_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.get_flow("recovery", id, cookie).await
    }

    /// Get an existing self-service verification flow by id.
    #[instrument(skip(self, cookie))]
    pub async fn get_verification_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.get_flow("verification", id, cookie).await
    }

    async fn get_flow(
        &self,
        flow_type: &str,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        let public_url = self
            .public_url
            .as_ref()
            .ok_or_else(|| OryClientError::InvalidResponse("kratos public url not set".into()))?;
        let url = public_url.join(&format!("self-service/{flow_type}/flows"))?;
        let mut request = self
            .client
            .get(url)
            .query(&[("id", id)])
            .header("accept", "application/json");
        if let Some(cookie) = cookie {
            request = request.header("Cookie", cookie);
        }
        let response = request.send().await.map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Submit a self-service login flow.
    #[instrument(skip(self, cookie, body))]
    pub async fn submit_login_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<Value, OryClientError> {
        self.submit_flow("login", id, cookie, body).await
    }

    /// Submit a self-service registration flow.
    #[instrument(skip(self, cookie, body))]
    pub async fn submit_registration_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<Value, OryClientError> {
        self.submit_flow("registration", id, cookie, body).await
    }

    /// Submit a self-service settings flow.
    #[instrument(skip(self, cookie, body))]
    pub async fn submit_settings_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<Value, OryClientError> {
        self.submit_flow("settings", id, cookie, body).await
    }

    /// Submit a self-service recovery flow.
    #[instrument(skip(self, cookie, body))]
    pub async fn submit_recovery_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<Value, OryClientError> {
        self.submit_flow("recovery", id, cookie, body).await
    }

    /// Submit a self-service verification flow.
    #[instrument(skip(self, cookie, body))]
    pub async fn submit_verification_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<Value, OryClientError> {
        self.submit_flow("verification", id, cookie, body).await
    }

    async fn submit_flow(
        &self,
        flow_type: &str,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<Value, OryClientError> {
        let public_url = self
            .public_url
            .as_ref()
            .ok_or_else(|| OryClientError::InvalidResponse("kratos public url not set".into()))?;
        let url = public_url.join(&format!("self-service/{flow_type}"))?;
        let mut request = self
            .client
            .post(url)
            .query(&[("flow", id)])
            .header("accept", "application/json")
            .json(&body);
        if let Some(cookie) = cookie {
            request = request.header("Cookie", cookie);
        }
        let response = request.send().await.map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Create a browser logout flow.
    #[instrument(skip(self, cookie))]
    pub async fn create_logout_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        let public_url = self
            .public_url
            .as_ref()
            .ok_or_else(|| OryClientError::InvalidResponse("kratos public url not set".into()))?;
        let url = public_url.join("self-service/logout/browser")?;
        let mut request = self.client.get(url).header("accept", "application/json");
        if let Some(return_to) = return_to {
            request = request.query(&[("return_to", return_to)]);
        }
        if let Some(cookie) = cookie {
            request = request.header("Cookie", cookie);
        }
        let response = request.send().await.map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Submit a logout flow using the token returned by `create_logout_flow`.
    #[instrument(skip(self, cookie))]
    pub async fn submit_logout_flow(
        &self,
        token: &str,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<(), OryClientError> {
        let public_url = self
            .public_url
            .as_ref()
            .ok_or_else(|| OryClientError::InvalidResponse("kratos public url not set".into()))?;
        let url = public_url.join("self-service/logout")?;
        let mut request = self
            .client
            .get(url)
            .query(&[("token", token)])
            .header("accept", "application/json");
        if let Some(return_to) = return_to {
            request = request.query(&[("return_to", return_to)]);
        }
        if let Some(cookie) = cookie {
            request = request.header("Cookie", cookie);
        }
        let response = request.send().await.map_err(OryClientError::Http)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ory_error(response).await)
        }
    }

    /// Create a browser verification flow.
    #[instrument(skip(self, cookie))]
    pub async fn create_verification_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.create_browser_flow("verification", return_to, cookie)
            .await
    }

    /// Create a browser login flow.
    #[instrument(skip(self, cookie))]
    pub async fn create_login_browser_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.create_browser_flow("login", return_to, cookie).await
    }

    /// Create a browser registration flow.
    #[instrument(skip(self, cookie))]
    pub async fn create_registration_browser_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.create_browser_flow("registration", return_to, cookie)
            .await
    }

    /// Create a browser settings flow.
    #[instrument(skip(self, cookie))]
    pub async fn create_settings_browser_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.create_browser_flow("settings", return_to, cookie)
            .await
    }

    /// Create a browser recovery flow.
    #[instrument(skip(self, cookie))]
    pub async fn create_recovery_browser_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.create_browser_flow("recovery", return_to, cookie)
            .await
    }

    #[instrument(skip(self, cookie))]
    async fn create_browser_flow(
        &self,
        flow: &str,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        let public_url = self
            .public_url
            .as_ref()
            .ok_or_else(|| OryClientError::InvalidResponse("kratos public url not set".into()))?;
        let url = public_url.join(&format!("self-service/{flow}/browser"))?;
        let mut request = self.client.get(url).header("accept", "application/json");
        if let Some(return_to) = return_to {
            request = request.query(&[("return_to", return_to)]);
        }
        if let Some(cookie) = cookie {
            request = request.header("Cookie", cookie);
        }
        let response = request.send().await.map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Get a self-service flow error by id.
    #[instrument(skip(self))]
    pub async fn get_flow_error(&self, id: &str) -> Result<Value, OryClientError> {
        let public_url = self
            .public_url
            .as_ref()
            .ok_or_else(|| OryClientError::InvalidResponse("kratos public url not set".into()))?;
        let url = public_url.join("self-service/errors")?;
        let request = self
            .client
            .get(url)
            .query(&[("id", id)])
            .header("accept", "application/json");
        let response = request.send().await.map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Fetch the WebAuthn JavaScript asset served by Kratos.
    #[instrument(skip(self))]
    pub async fn get_webauthn_js(&self) -> Result<String, OryClientError> {
        let public_url = self
            .public_url
            .as_ref()
            .ok_or_else(|| OryClientError::InvalidResponse("kratos public url not set".into()))?;
        let url = public_url.join(".well-known/ory/webauthn.js")?;
        let response = self
            .client
            .get(url)
            .header("accept", "application/javascript")
            .send()
            .await
            .map_err(OryClientError::Http)?;
        if response.status().is_success() {
            response.text().await.map_err(OryClientError::Http)
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
    use axum::{
        Json, Router,
        extract::Query,
        routing::{get, post},
    };
    use serde_json::json;

    use super::*;

    fn app() -> Router {
        let admin = Router::new()
            .route("/admin/identities", post(create_identity))
            .route(
                "/admin/identities/{id}",
                get(get_identity)
                    .put(update_identity)
                    .delete(delete_identity),
            )
            .route("/schemas/{id}", get(get_schema));

        let public = Router::new()
            .route("/sessions/whoami", get(whoami))
            .route("/self-service/{flow}/browser", get(create_browser_flow))
            .route("/self-service/login/flows", get(get_login_flow))
            .route("/self-service/login", post(submit_login_flow))
            .route("/self-service/logout/browser", get(create_logout_flow))
            .route("/self-service/logout", get(submit_logout_flow))
            .route("/self-service/errors", get(get_flow_error))
            .route("/.well-known/ory/webauthn.js", get(webauthn_js));

        Router::new().merge(admin).merge(public)
    }

    async fn create_identity(Json(body): Json<Value>) -> Json<Value> {
        Json(json!({
            "id": "identity-1",
            "traits": body.get("traits").cloned().unwrap_or_default(),
        }))
    }

    async fn get_identity(axum::extract::Path(id): axum::extract::Path<String>) -> Json<Value> {
        Json(json!({ "id": id, "traits": {} }))
    }

    async fn update_identity(
        axum::extract::Path(id): axum::extract::Path<String>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        Json(json!({ "id": id, "traits": body.get("traits").cloned().unwrap_or_default() }))
    }

    async fn delete_identity() -> axum::http::StatusCode {
        axum::http::StatusCode::NO_CONTENT
    }

    async fn get_schema(axum::extract::Path(id): axum::extract::Path<String>) -> Json<Value> {
        Json(json!({ "id": id, "schema": "{}" }))
    }

    async fn create_browser_flow(
        axum::extract::Path(flow): axum::extract::Path<String>,
        Query(params): Query<std::collections::HashMap<String, String>>,
    ) -> Json<Value> {
        Json(json!({
            "id": format!("{flow}-1"),
            "type": flow,
            "return_to": params.get("return_to").cloned().unwrap_or_default()
        }))
    }

    async fn whoami(headers: axum::http::HeaderMap) -> Json<Value> {
        let token = headers
            .get("x-session-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let cookie = headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        Json(json!({
            "id": "session-1",
            "active": true,
            "identity": { "id": "identity-1", "traits": { "email": "a@example.com" } },
            "token": token,
            "cookie": cookie,
        }))
    }

    async fn get_login_flow(
        Query(params): Query<std::collections::HashMap<String, String>>,
    ) -> Json<Value> {
        Json(json!({
            "id": params.get("id").cloned().unwrap_or_default(),
            "type": "login",
            "state": "choose_method"
        }))
    }

    async fn submit_login_flow(
        Query(params): Query<std::collections::HashMap<String, String>>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        Json(json!({
            "id": params.get("flow").cloned().unwrap_or_default(),
            "type": "login",
            "state": "passed_challenge",
            "body": body
        }))
    }

    async fn create_logout_flow(
        Query(params): Query<std::collections::HashMap<String, String>>,
    ) -> Json<Value> {
        Json(json!({
            "id": "logout-1",
            "logout_url": "http://logout",
            "logout_token": "token-1",
            "return_to": params.get("return_to").cloned().unwrap_or_default()
        }))
    }

    async fn submit_logout_flow(
        Query(params): Query<std::collections::HashMap<String, String>>,
    ) -> Json<Value> {
        Json(json!({
            "token": params.get("token").cloned().unwrap_or_default()
        }))
    }

    async fn get_flow_error(
        Query(params): Query<std::collections::HashMap<String, String>>,
    ) -> Json<Value> {
        Json(json!({
            "id": params.get("id").cloned().unwrap_or_default(),
            "error": { "message": "oops" }
        }))
    }

    async fn webauthn_js() -> (axum::http::StatusCode, &'static str) {
        (axum::http::StatusCode::OK, "console.log('webauthn');")
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
    async fn create_identity_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new(&url).unwrap();
        let resp = client
            .create_identity(json!({"traits": {"email": "a@example.com"}}))
            .await
            .unwrap();
        assert_eq!(resp["id"], "identity-1");
        assert_eq!(resp["traits"]["email"], "a@example.com");
    }

    #[tokio::test]
    async fn get_identity_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new(&url).unwrap();
        let resp = client.get_identity("identity-1").await.unwrap();
        assert_eq!(resp["id"], "identity-1");
    }

    #[tokio::test]
    async fn update_identity_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new(&url).unwrap();
        let resp = client
            .update_identity("identity-1", json!({"traits": {"email": "b@example.com"}}))
            .await
            .unwrap();
        assert_eq!(resp["id"], "identity-1");
        assert_eq!(resp["traits"]["email"], "b@example.com");
    }

    #[tokio::test]
    async fn delete_identity_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new(&url).unwrap();
        client.delete_identity("identity-1").await.unwrap();
    }

    #[tokio::test]
    async fn get_identity_schema_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new(&url).unwrap();
        let resp = client.get_identity_schema("default").await.unwrap();
        assert_eq!(resp["id"], "default");
    }

    #[tokio::test]
    async fn to_session_with_cookie_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .to_session(Some("ory_kratos_session=abc"), None)
            .await
            .unwrap();
        assert_eq!(resp["id"], "session-1");
        assert_eq!(resp["cookie"], "ory_kratos_session=abc");
    }

    #[tokio::test]
    async fn to_session_with_token_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client.to_session(None, Some("token-1")).await.unwrap();
        assert_eq!(resp["token"], "token-1");
    }

    #[tokio::test]
    async fn get_login_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .get_login_flow("flow-1", Some("cookie"))
            .await
            .unwrap();
        assert_eq!(resp["id"], "flow-1");
        assert_eq!(resp["type"], "login");
    }

    #[tokio::test]
    async fn submit_login_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .submit_login_flow("flow-1", Some("cookie"), json!({ "identifier": "a" }))
            .await
            .unwrap();
        assert_eq!(resp["id"], "flow-1");
        assert_eq!(resp["state"], "passed_challenge");
        assert_eq!(resp["body"]["identifier"], "a");
    }

    #[tokio::test]
    async fn create_login_browser_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .create_login_browser_flow(Some("http://return"), Some("cookie"))
            .await
            .unwrap();
        assert_eq!(resp["id"], "login-1");
        assert_eq!(resp["type"], "login");
        assert_eq!(resp["return_to"], "http://return");
    }

    #[tokio::test]
    async fn create_registration_browser_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .create_registration_browser_flow(Some("http://return"), Some("cookie"))
            .await
            .unwrap();
        assert_eq!(resp["id"], "registration-1");
        assert_eq!(resp["type"], "registration");
    }

    #[tokio::test]
    async fn create_settings_browser_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .create_settings_browser_flow(Some("http://return"), Some("cookie"))
            .await
            .unwrap();
        assert_eq!(resp["id"], "settings-1");
        assert_eq!(resp["type"], "settings");
    }

    #[tokio::test]
    async fn create_recovery_browser_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .create_recovery_browser_flow(Some("http://return"), Some("cookie"))
            .await
            .unwrap();
        assert_eq!(resp["id"], "recovery-1");
        assert_eq!(resp["type"], "recovery");
    }

    #[tokio::test]
    async fn create_logout_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .create_logout_flow(Some("http://return"), Some("cookie"))
            .await
            .unwrap();
        assert_eq!(resp["id"], "logout-1");
        assert_eq!(resp["return_to"], "http://return");
    }

    #[tokio::test]
    async fn submit_logout_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        client
            .submit_logout_flow("token-1", None, Some("cookie"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn get_flow_error_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client.get_flow_error("error-1").await.unwrap();
        assert_eq!(resp["id"], "error-1");
    }

    #[tokio::test]
    async fn get_webauthn_js_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client.get_webauthn_js().await.unwrap();
        assert_eq!(resp, "console.log('webauthn');");
    }
}
