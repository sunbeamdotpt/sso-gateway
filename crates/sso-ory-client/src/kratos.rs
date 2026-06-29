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
        routing::{get, post},
    };
    use serde_json::json;

    use super::*;

    fn app() -> Router {
        Router::new()
            .route("/admin/identities", post(create_identity))
            .route(
                "/admin/identities/{id}",
                get(get_identity)
                    .put(update_identity)
                    .delete(delete_identity),
            )
            .route("/schemas/{id}", get(get_schema))
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
}
