use reqwest::header::HeaderMap;
use reqwest::{Client, Method, Url};
use serde_json::Value;
use tracing::{debug, instrument};

use crate::error::OryClientError;

/// A successful Kratos response, carrying both the JSON body and the response
/// headers so that caller can propagate cookies (e.g. `Set-Cookie`).
#[derive(Debug, Clone)]
pub struct KratosResponse {
    pub body: Value,
    pub headers: HeaderMap,
}

/// A redirect-style Kratos response, carrying the `Location` header and any
/// `Set-Cookie` headers from a 302 self-service token exchange.
#[derive(Debug, Clone)]
pub struct KratosRedirectResponse {
    pub location: Option<String>,
    pub headers: HeaderMap,
}

/// Internal client for Ory Kratos (admin and public endpoints).
#[derive(Debug, Clone)]
pub struct KratosClient {
    client: Client,
    no_redirect_client: Client,
    admin_url: Url,
    public_url: Option<Url>,
}

impl KratosClient {
    fn build_client() -> Result<Client, OryClientError> {
        Ok(Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()?)
    }

    fn build_no_redirect_client() -> Result<Client, OryClientError> {
        Ok(Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()?)
    }

    /// Create a new Kratos admin client.
    pub fn new(admin_url: &str) -> Result<Self, OryClientError> {
        Ok(Self {
            client: Self::build_client()?,
            no_redirect_client: Self::build_no_redirect_client()?,
            admin_url: parse_base_url(admin_url)?,
            public_url: None,
        })
    }

    /// Create a client with both admin and public endpoints configured.
    pub fn new_with_public(admin_url: &str, public_url: &str) -> Result<Self, OryClientError> {
        Ok(Self {
            client: Self::build_client()?,
            no_redirect_client: Self::build_no_redirect_client()?,
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
        let url = self
            .admin_url
            .join(&format!("admin/identities/{}", urlencoding::encode(id)))?;
        debug!(%url, "fetching kratos identity");
        self.send_json(Method::GET, url, None).await
    }

    /// Update an identity by its Ory global id.
    #[instrument(skip(self, payload), fields(admin_url = %self.admin_url))]
    pub async fn update_identity(&self, id: &str, payload: Value) -> Result<Value, OryClientError> {
        let url = self
            .admin_url
            .join(&format!("admin/identities/{}", urlencoding::encode(id)))?;
        debug!(%url, "updating kratos identity");
        self.send_json(Method::PUT, url, Some(payload)).await
    }

    /// Delete an identity by its Ory global id.
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn delete_identity(&self, id: &str) -> Result<(), OryClientError> {
        let url = self
            .admin_url
            .join(&format!("admin/identities/{}", urlencoding::encode(id)))?;
        debug!(%url, "deleting kratos identity");
        self.send_empty(Method::DELETE, url).await
    }

    /// List identities by a tenant-scoped credential identifier (e.g. email address).
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn list_identities_by_identifier(
        &self,
        tenant_id: &str,
        identifier: &str,
    ) -> Result<Value, OryClientError> {
        let url = self.admin_url.join("admin/identities")?;
        debug!(%url, %tenant_id, %identifier, "listing kratos identities by identifier");
        let response = self
            .client
            .get(url)
            .query(&[
                ("credentials_identifier", identifier),
                ("tenant_id", tenant_id),
            ])
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Create a browser session for an existing identity via the admin API.
    ///
    /// Returns the full response so callers can propagate `Set-Cookie` headers.
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn create_session_for_identity(
        &self,
        identity_id: &str,
        amr: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        let url = self.admin_url.join(&format!(
            "admin/identities/{}/sessions",
            urlencoding::encode(identity_id)
        ))?;
        debug!(%url, %identity_id, "creating kratos session for identity");
        let mut body = serde_json::json!({ "session_token": true });
        if let Some(amr) = amr {
            body["authentication_methods"] = serde_json::json!([{ "method": amr }]);
        }
        let response = self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response_with_headers(response).await
    }

    /// Get the active identity schema.
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn get_identity_schema(&self, id: &str) -> Result<Value, OryClientError> {
        let url = self
            .admin_url
            .join(&format!("schemas/{}", urlencoding::encode(id)))?;
        debug!(%url, "fetching kratos identity schema");
        self.send_json(Method::GET, url, None).await
    }

    /// Get a session by its Ory global id.
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn admin_get_session(&self, id: &str) -> Result<Value, OryClientError> {
        let url = self
            .admin_url
            .join(&format!("admin/sessions/{}", urlencoding::encode(id)))?;
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
        let url = self
            .admin_url
            .join(&format!("admin/sessions/{}", urlencoding::encode(id)))?;
        debug!(%url, "deleting kratos session");
        self.send_empty(Method::DELETE, url).await
    }

    /// Create a recovery link for an identity via the admin API.
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn create_recovery_link(
        &self,
        identity_id: &str,
        expires_in_seconds: Option<i64>,
    ) -> Result<KratosResponse, OryClientError> {
        let url = self.admin_url.join("admin/recovery/link")?;
        debug!(%url, %identity_id, "creating kratos recovery link");
        let mut body = serde_json::json!({ "identity_id": identity_id });
        if let Some(seconds) = expires_in_seconds {
            body["expires_in"] = serde_json::json!(format!("{seconds}s"));
        }
        let response = self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response_with_headers(response).await
    }

    /// List courier messages via the admin API.
    #[instrument(skip(self), fields(admin_url = %self.admin_url))]
    pub async fn list_courier_messages(
        &self,
        identity_id: Option<&str>,
        message_type: Option<&str>,
    ) -> Result<Value, OryClientError> {
        let url = self.admin_url.join("admin/courier/messages")?;
        debug!(%url, "listing kratos courier messages");
        let mut request = self.client.get(url);
        let mut query = Vec::<(&str, &str)>::new();
        if let Some(identity_id) = identity_id {
            query.push(("identity_id", identity_id));
        }
        if let Some(message_type) = message_type {
            query.push(("template_type", message_type));
        }
        if !query.is_empty() {
            request = request.query(&query);
        }
        let response = request.send().await.map_err(OryClientError::Http)?;
        handle_response(response).await
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
    pub async fn create_login_flow(&self, query: &[(&str, &str)]) -> Result<Value, OryClientError> {
        let public_url = self
            .public_url
            .as_ref()
            .ok_or_else(|| OryClientError::InvalidResponse("kratos public url not set".into()))?;
        let url = public_url.join("self-service/login/api")?;
        let mut request = self.client.get(url).header("accept", "application/json");
        if !query.is_empty() {
            request = request.query(query);
        }
        let response = request.send().await.map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Create a self-service registration flow via the public API.
    #[instrument(skip(self))]
    pub async fn create_registration_flow(
        &self,
        query: &[(&str, &str)],
    ) -> Result<Value, OryClientError> {
        let public_url = self
            .public_url
            .as_ref()
            .ok_or_else(|| OryClientError::InvalidResponse("kratos public url not set".into()))?;
        let url = public_url.join("self-service/registration/api")?;
        let mut request = self.client.get(url).header("accept", "application/json");
        if !query.is_empty() {
            request = request.query(query);
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
    ) -> Result<KratosResponse, OryClientError> {
        self.get_flow("login", id, cookie).await
    }

    /// Get an existing self-service registration flow by id.
    #[instrument(skip(self, cookie))]
    pub async fn get_registration_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        self.get_flow("registration", id, cookie).await
    }

    /// Get an existing self-service settings flow by id.
    #[instrument(skip(self, cookie))]
    pub async fn get_settings_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        self.get_flow("settings", id, cookie).await
    }

    /// Get an existing self-service recovery flow by id.
    #[instrument(skip(self, cookie))]
    pub async fn get_recovery_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        self.get_flow("recovery", id, cookie).await
    }

    /// Get an existing self-service verification flow by id.
    #[instrument(skip(self, cookie))]
    pub async fn get_verification_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        self.get_flow("verification", id, cookie).await
    }

    async fn get_flow(
        &self,
        flow_type: &str,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        let public_url = self
            .public_url
            .as_ref()
            .ok_or_else(|| OryClientError::InvalidResponse("kratos public url not set".into()))?;
        let url = public_url.join(&format!(
            "self-service/{}/flows",
            urlencoding::encode(flow_type)
        ))?;
        let mut request = self
            .client
            .get(url)
            .query(&[("id", id)])
            .header("accept", "application/json");
        if let Some(cookie) = cookie {
            request = request.header("Cookie", cookie);
        }
        let response = request.send().await.map_err(OryClientError::Http)?;
        handle_response_with_headers(response).await
    }

    /// Submit a self-service login flow.
    #[instrument(skip(self, cookie, body))]
    pub async fn submit_login_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<KratosResponse, OryClientError> {
        self.submit_flow("login", id, cookie, body).await
    }

    /// Submit a self-service registration flow.
    #[instrument(skip(self, cookie, body))]
    pub async fn submit_registration_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<KratosResponse, OryClientError> {
        self.submit_flow("registration", id, cookie, body).await
    }

    /// Submit a self-service settings flow.
    #[instrument(skip(self, cookie, body))]
    pub async fn submit_settings_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<KratosResponse, OryClientError> {
        self.submit_flow("settings", id, cookie, body).await
    }

    /// Submit a self-service recovery flow.
    #[instrument(skip(self, cookie, body))]
    pub async fn submit_recovery_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<KratosResponse, OryClientError> {
        self.submit_flow("recovery", id, cookie, body).await
    }

    /// Submit a self-service verification flow.
    #[instrument(skip(self, cookie, body))]
    pub async fn submit_verification_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<KratosResponse, OryClientError> {
        self.submit_flow("verification", id, cookie, body).await
    }

    async fn submit_flow(
        &self,
        flow_type: &str,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<KratosResponse, OryClientError> {
        let public_url = self
            .public_url
            .as_ref()
            .ok_or_else(|| OryClientError::InvalidResponse("kratos public url not set".into()))?;
        let url = public_url.join(&format!("self-service/{}", urlencoding::encode(flow_type)))?;
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
        handle_response_with_headers(response).await
    }

    /// Create a browser logout flow.
    #[instrument(skip(self, cookie))]
    pub async fn create_logout_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
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
        handle_response_with_headers(response).await
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
    ) -> Result<KratosResponse, OryClientError> {
        let query = match return_to {
            Some(r) => vec![("return_to", r)],
            None => Vec::new(),
        };
        self.create_browser_flow("verification", &query, cookie)
            .await
    }

    /// Create a browser login flow.
    #[instrument(skip(self, cookie))]
    pub async fn create_login_browser_flow(
        &self,
        query: &[(&str, &str)],
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        self.create_browser_flow("login", query, cookie).await
    }

    /// Create a browser registration flow.
    #[instrument(skip(self, cookie))]
    pub async fn create_registration_browser_flow(
        &self,
        query: &[(&str, &str)],
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        self.create_browser_flow("registration", query, cookie)
            .await
    }

    /// Create a browser settings flow.
    #[instrument(skip(self, cookie))]
    pub async fn create_settings_browser_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        let query = match return_to {
            Some(r) => vec![("return_to", r)],
            None => Vec::new(),
        };
        self.create_browser_flow("settings", &query, cookie).await
    }

    /// Create a browser recovery flow.
    #[instrument(skip(self, cookie))]
    pub async fn create_recovery_browser_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        let query = match return_to {
            Some(r) => vec![("return_to", r)],
            None => Vec::new(),
        };
        self.create_browser_flow("recovery", &query, cookie).await
    }

    #[instrument(skip(self, cookie))]
    async fn create_browser_flow(
        &self,
        flow: &str,
        query: &[(&str, &str)],
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        let public_url = self
            .public_url
            .as_ref()
            .ok_or_else(|| OryClientError::InvalidResponse("kratos public url not set".into()))?;
        let url = public_url.join(&format!(
            "self-service/{}/browser",
            urlencoding::encode(flow)
        ))?;
        let mut request = self.client.get(url).header("accept", "application/json");
        if !query.is_empty() {
            request = request.query(query);
        }
        if let Some(cookie) = cookie {
            request = request.header("Cookie", cookie);
        }
        let response = request.send().await.map_err(OryClientError::Http)?;
        handle_response_with_headers(response).await
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

    /// Submit a recovery magic-link token to Kratos and capture the redirect.
    #[instrument(skip(self, cookie, csrf_token))]
    pub async fn submit_recovery_token(
        &self,
        token: &str,
        flow: &str,
        cookie: Option<&str>,
        csrf_token: Option<&str>,
    ) -> Result<KratosRedirectResponse, OryClientError> {
        self.submit_token("recovery", token, Some(flow), cookie, csrf_token)
            .await
    }

    /// Submit a verification magic-link token to Kratos and capture the redirect.
    #[instrument(skip(self, cookie, csrf_token))]
    pub async fn submit_verification_token(
        &self,
        token: &str,
        flow: &str,
        cookie: Option<&str>,
        csrf_token: Option<&str>,
    ) -> Result<KratosRedirectResponse, OryClientError> {
        self.submit_token("verification", token, Some(flow), cookie, csrf_token)
            .await
    }

    async fn submit_token(
        &self,
        flow_type: &str,
        token: &str,
        flow: Option<&str>,
        cookie: Option<&str>,
        csrf_token: Option<&str>,
    ) -> Result<KratosRedirectResponse, OryClientError> {
        let public_url = self
            .public_url
            .as_ref()
            .ok_or_else(|| OryClientError::InvalidResponse("kratos public url not set".into()))?;
        let url = public_url.join(&format!("self-service/{}", urlencoding::encode(flow_type)))?;
        let mut query: Vec<(&str, &str)> = Vec::new();
        if let Some(flow) = flow {
            query.push(("flow", flow));
        }
        query.push(("token", token));
        let mut request = self
            .no_redirect_client
            .get(url)
            .query(&query)
            .header("accept", "text/html");
        if let Some(cookie) = cookie {
            request = request.header("Cookie", cookie);
        }
        if let Some(csrf_token) = csrf_token {
            request = request.header("X-CSRF-Token", csrf_token);
        }
        let response = request.send().await.map_err(OryClientError::Http)?;
        if response.status().is_redirection() {
            let headers = response.headers().clone();
            Ok(KratosRedirectResponse {
                location: headers
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from),
                headers,
            })
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
    Ok(handle_response_with_headers(response).await?.body)
}

async fn handle_response_with_headers(
    response: reqwest::Response,
) -> Result<KratosResponse, OryClientError> {
    if response.status().is_success() {
        let headers = response.headers().clone();
        let body = response.json().await.map_err(OryClientError::Http)?;
        Ok(KratosResponse { body, headers })
    } else if response.status() == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
        Err(browser_redirect_or_error(response).await)
    } else {
        Err(ory_error(response).await)
    }
}

/// Kratos answers a successful browser submit that must continue elsewhere
/// (login challenge, `return_to`) with 422 `browser_location_change_required`.
/// The session `Set-Cookie` rides on that 422 response, so surface the target
/// and the cookies via [`OryClientError::Redirect`] instead of a bare error.
/// Any other 422 keeps the plain error behavior.
async fn browser_redirect_or_error(response: reqwest::Response) -> OryClientError {
    let headers = response.headers().clone();
    let status = response.status().as_u16();
    let message = match response.text().await {
        Ok(body) => body,
        Err(err) => {
            tracing::warn!(%err, "failed to read kratos error body; falling back to placeholder");
            "<unreadable body>".to_string()
        }
    };
    let body: Value = match serde_json::from_str(&message) {
        Ok(body) => body,
        Err(_) => return OryClientError::Ory { status, message },
    };
    let is_browser_redirect = body
        .get("error")
        .and_then(|error| error.get("id"))
        .and_then(Value::as_str)
        == Some("browser_location_change_required");
    if !is_browser_redirect {
        return OryClientError::Ory { status, message };
    }
    let location = match body.get("redirect_browser_to").and_then(Value::as_str) {
        Some(location) => location.to_string(),
        None => String::new(),
    };
    let set_cookies = headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .map(String::from)
        .collect();
    OryClientError::Redirect {
        location,
        set_cookies,
    }
}

async fn ory_error(response: reqwest::Response) -> OryClientError {
    let status = response.status().as_u16();
    let message = match response.text().await {
        Ok(body) => body,
        Err(err) => {
            tracing::warn!(%err, "failed to read kratos error body; falling back to placeholder");
            "<unreadable body>".to_string()
        }
    };
    OryClientError::Ory { status, message }
}

#[cfg(test)]
mod tests {
    use axum::{
        Json, Router,
        extract::Query,
        routing::{delete, get, post, put},
    };
    use serde_json::json;

    use super::*;

    fn app() -> Router {
        let admin = Router::new()
            .route(
                "/admin/identities",
                get(list_identities).post(create_identity),
            )
            .route(
                "/admin/identities/{id}",
                get(get_identity)
                    .put(update_identity)
                    .delete(delete_identity),
            )
            .route(
                "/admin/identities/{id}/sessions",
                post(create_session_for_identity),
            )
            .route("/admin/sessions", get(list_sessions))
            .route(
                "/admin/sessions/{id}",
                get(get_session).delete(delete_session),
            )
            .route("/admin/recovery/link", post(create_recovery_link))
            .route("/admin/courier/messages", get(list_courier_messages))
            .route("/schemas/{id}", get(get_schema));

        let public = Router::new()
            .route("/sessions/whoami", get(whoami))
            .route("/self-service/{flow}/api", get(create_api_flow))
            .route("/self-service/{flow}/browser", get(create_browser_flow))
            .route("/self-service/{flow}/flows", get(get_flow))
            .route("/self-service/logout", get(submit_logout_flow))
            .route("/self-service/logout/browser", get(create_logout_flow))
            .route("/self-service/errors", get(get_flow_error))
            .route(
                "/self-service/recovery",
                get(submit_recovery_token).post(submit_recovery_flow_post),
            )
            .route(
                "/self-service/verification",
                get(submit_verification_token).post(submit_verification_flow_post),
            )
            .route("/self-service/{flow}", post(submit_flow))
            .route("/.well-known/ory/webauthn.js", get(webauthn_js));

        Router::new().merge(admin).merge(public)
    }

    async fn create_identity(Json(body): Json<Value>) -> Json<Value> {
        Json(json!({
            "id": "identity-1",
            "traits": body.get("traits").cloned().unwrap_or_default(),
        }))
    }

    async fn list_identities(
        Query(params): Query<std::collections::HashMap<String, String>>,
    ) -> Json<Value> {
        let identifier = params
            .get("credentials_identifier")
            .cloned()
            .unwrap_or_default();
        let tenant_id = params.get("tenant_id").cloned().unwrap_or_default();
        if identifier == "found@example.com" && tenant_id == "tenant-1" {
            Json(json!([
                { "id": "identity-found", "traits": { "email": identifier } }
            ]))
        } else {
            Json(json!([]))
        }
    }

    async fn create_session_for_identity(
        axum::extract::Path(id): axum::extract::Path<String>,
        Json(body): Json<Value>,
    ) -> (axum::http::StatusCode, axum::http::HeaderMap, Json<Value>) {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "set-cookie",
            format!("ory_kratos_session={id}; Path=/; HttpOnly")
                .parse()
                .unwrap(),
        );
        (
            axum::http::StatusCode::CREATED,
            headers,
            Json(json!({
                "id": "session-created",
                "identity": { "id": id },
                "token": body.get("session_token").and_then(|v| v.as_bool()).unwrap_or(false),
            })),
        )
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

    async fn list_sessions(
        Query(params): Query<std::collections::HashMap<String, String>>,
    ) -> Json<Value> {
        Json(json!({
            "identity_id": params.get("identity_id").cloned().unwrap_or_default(),
            "sessions": []
        }))
    }

    async fn get_session(axum::extract::Path(id): axum::extract::Path<String>) -> Json<Value> {
        Json(json!({ "id": id, "active": true }))
    }

    async fn delete_session() -> axum::http::StatusCode {
        axum::http::StatusCode::NO_CONTENT
    }

    async fn create_recovery_link(Json(body): Json<Value>) -> Json<Value> {
        let identity_id = body
            .get("identity_id")
            .and_then(|v| v.as_str())
            .unwrap_or("identity-1");
        let expires_in = body
            .get("expires_in")
            .and_then(|v| v.as_str())
            .unwrap_or("1h");
        Json(json!({
            "recovery_link": format!("http://kratos.example.com/self-service/recovery?flow={identity_id}-recovery-flow&token={identity_id}-recovery-token"),
            "recovery_token": format!("{identity_id}-recovery-token"),
            "expires_at": "2026-01-01T00:00:00Z",
            "expires_in": expires_in,
        }))
    }

    async fn list_courier_messages(
        Query(params): Query<std::collections::HashMap<String, String>>,
    ) -> Json<Value> {
        let identity_id = params.get("identity_id").cloned().unwrap_or_default();
        let template_type = params.get("template_type").cloned().unwrap_or_default();
        Json(json!([
            {
                "id": "message-1",
                "type": "email",
                "subject": "Verify your email",
                "body": format!("Click <a href=\"http://kratos.example.com/self-service/verification?flow={identity_id}-verification-flow&token={identity_id}-verify-token\">here</a>"),
                "status": "sent",
                "recipient": "a@example.com",
                "sent_at": "2025-01-01T00:00:00Z",
                "template_type": template_type,
            }
        ]))
    }

    async fn create_api_flow(
        axum::extract::Path(flow): axum::extract::Path<String>,
    ) -> Json<Value> {
        Json(json!({
            "id": format!("{flow}-1"),
            "type": flow,
            "state": "choose_method"
        }))
    }

    async fn create_browser_flow(
        axum::extract::Path(flow): axum::extract::Path<String>,
        Query(params): Query<std::collections::HashMap<String, String>>,
    ) -> (axum::http::StatusCode, axum::http::HeaderMap, Json<Value>) {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "set-cookie",
            format!("ory_kratos_session={flow}; Path=/; HttpOnly")
                .parse()
                .unwrap(),
        );
        (
            axum::http::StatusCode::OK,
            headers,
            Json(json!({
                "id": format!("{flow}-1"),
                "type": flow,
                "return_to": params.get("return_to").cloned().unwrap_or_default()
            })),
        )
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

    async fn get_flow(
        axum::extract::Path(flow): axum::extract::Path<String>,
        Query(params): Query<std::collections::HashMap<String, String>>,
    ) -> (axum::http::StatusCode, axum::http::HeaderMap, Json<Value>) {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "set-cookie",
            format!("ory_kratos_session={flow}; Path=/; HttpOnly")
                .parse()
                .unwrap(),
        );
        (
            axum::http::StatusCode::OK,
            headers,
            Json(json!({
                "id": params.get("id").cloned().unwrap_or_default(),
                "type": flow,
                "state": "choose_method"
            })),
        )
    }

    async fn submit_flow(
        axum::extract::Path(flow): axum::extract::Path<String>,
        Query(params): Query<std::collections::HashMap<String, String>>,
        Json(body): Json<Value>,
    ) -> (axum::http::StatusCode, axum::http::HeaderMap, Json<Value>) {
        submit_flow_inner(&flow, params, body).await
    }

    async fn submit_flow_inner(
        flow: &str,
        params: std::collections::HashMap<String, String>,
        body: Value,
    ) -> (axum::http::StatusCode, axum::http::HeaderMap, Json<Value>) {
        let flow_id = params.get("flow").cloned().unwrap_or_default();
        let mut headers = axum::http::HeaderMap::new();
        if flow_id == "flow-422-redirect" {
            headers.append(
                "set-cookie",
                "ory_kratos_session=session-422; Path=/; HttpOnly"
                    .parse()
                    .unwrap(),
            );
            headers.append(
                "set-cookie",
                "csrf_token_422=xyz; Path=/; HttpOnly".parse().unwrap(),
            );
            return (
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                headers,
                Json(json!({
                    "error": {
                        "id": "browser_location_change_required",
                        "code": 422,
                        "reason": "The browser needs to be redirected to a different location.",
                    },
                    "redirect_browser_to": "https://gateway.example.com/oauth2/auth?login_verifier=v1",
                })),
            );
        }
        if flow_id == "flow-422-other" {
            return (
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                headers,
                Json(json!({
                    "error": {
                        "id": "session_already_available",
                        "code": 422,
                        "reason": "Already logged in.",
                    },
                })),
            );
        }
        headers.insert(
            "set-cookie",
            format!("ory_kratos_session={flow}; Path=/; HttpOnly")
                .parse()
                .unwrap(),
        );
        (
            axum::http::StatusCode::OK,
            headers,
            Json(json!({
                "id": flow_id,
                "type": flow,
                "state": "passed_challenge",
                "body": body
            })),
        )
    }

    async fn submit_recovery_flow_post(
        Query(params): Query<std::collections::HashMap<String, String>>,
        Json(body): Json<Value>,
    ) -> (axum::http::StatusCode, axum::http::HeaderMap, Json<Value>) {
        submit_flow_inner("recovery", params, body).await
    }

    async fn submit_verification_flow_post(
        Query(params): Query<std::collections::HashMap<String, String>>,
        Json(body): Json<Value>,
    ) -> (axum::http::StatusCode, axum::http::HeaderMap, Json<Value>) {
        submit_flow_inner("verification", params, body).await
    }

    async fn submit_recovery_token(
        Query(params): Query<std::collections::HashMap<String, String>>,
        headers: axum::http::HeaderMap,
    ) -> Result<(axum::http::StatusCode, axum::http::HeaderMap, Json<Value>), axum::http::StatusCode>
    {
        let token = params.get("token").cloned().unwrap_or_default();
        let flow = params.get("flow").cloned().unwrap_or_default();
        if token != "valid-recovery-token" || flow != "recovery-flow-id" {
            return Err(axum::http::StatusCode::BAD_REQUEST);
        }
        let csrf = headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let mut resp_headers = axum::http::HeaderMap::new();
        resp_headers.append(
            "set-cookie",
            format!("ory_kratos_session=recovery-{csrf}; Path=/; HttpOnly")
                .parse()
                .unwrap(),
        );
        resp_headers.append(
            "set-cookie",
            "csrf_token_1234=abc; Path=/; HttpOnly".parse().unwrap(),
        );
        resp_headers.insert(
            "location",
            "https://ui.example.com/recovery?flow=recovery-flow-id"
                .parse()
                .unwrap(),
        );
        Ok((axum::http::StatusCode::FOUND, resp_headers, Json(json!({}))))
    }

    async fn submit_verification_token(
        Query(params): Query<std::collections::HashMap<String, String>>,
        headers: axum::http::HeaderMap,
    ) -> Result<(axum::http::StatusCode, axum::http::HeaderMap, Json<Value>), axum::http::StatusCode>
    {
        let token = params.get("token").cloned().unwrap_or_default();
        let flow = params.get("flow").cloned().unwrap_or_default();
        if token != "valid-verification-token" || flow != "verification-flow-id" {
            return Err(axum::http::StatusCode::BAD_REQUEST);
        }
        let cookie = headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let mut resp_headers = axum::http::HeaderMap::new();
        resp_headers.insert(
            "set-cookie",
            "ory_kratos_session=verification; Path=/; HttpOnly"
                .parse()
                .unwrap(),
        );
        resp_headers.insert(
            "location",
            format!("https://ui.example.com/verification?flow={cookie}")
                .parse()
                .unwrap(),
        );
        Ok((axum::http::StatusCode::FOUND, resp_headers, Json(json!({}))))
    }

    async fn create_logout_flow(
        Query(params): Query<std::collections::HashMap<String, String>>,
    ) -> (axum::http::StatusCode, axum::http::HeaderMap, Json<Value>) {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "set-cookie",
            "ory_kratos_session=; Path=/; Max-Age=0; HttpOnly"
                .parse()
                .unwrap(),
        );
        (
            axum::http::StatusCode::OK,
            headers,
            Json(json!({
                "id": "logout-1",
                "logout_url": "http://logout",
                "logout_token": "token-1",
                "return_to": params.get("return_to").cloned().unwrap_or_default()
            })),
        )
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
        assert_eq!(resp.body["id"], "flow-1");
        assert_eq!(resp.body["type"], "login");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .contains("ory_kratos_session=login")
        );
    }

    #[tokio::test]
    async fn submit_login_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .submit_login_flow("flow-1", Some("cookie"), json!({ "identifier": "a" }))
            .await
            .unwrap();
        assert_eq!(resp.body["id"], "flow-1");
        assert_eq!(resp.body["state"], "passed_challenge");
        assert_eq!(resp.body["body"]["identifier"], "a");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .contains("ory_kratos_session=login")
        );
    }

    #[tokio::test]
    async fn submit_login_flow_captures_browser_location_change_redirect_and_cookies() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let err = client
            .submit_login_flow(
                "flow-422-redirect",
                Some("cookie"),
                json!({ "identifier": "a" }),
            )
            .await
            .unwrap_err();
        match err {
            OryClientError::Redirect {
                location,
                set_cookies,
            } => {
                assert_eq!(
                    location,
                    "https://gateway.example.com/oauth2/auth?login_verifier=v1"
                );
                assert_eq!(set_cookies.len(), 2);
                assert!(set_cookies[0].contains("ory_kratos_session=session-422"));
                assert!(set_cookies[1].contains("csrf_token_422=xyz"));
            }
            other => panic!("expected redirect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn submit_login_flow_preserves_other_422_errors() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let err = client
            .submit_login_flow(
                "flow-422-other",
                Some("cookie"),
                json!({ "identifier": "a" }),
            )
            .await
            .unwrap_err();
        match err {
            OryClientError::Ory { status, message } => {
                assert_eq!(status, 422);
                assert!(message.contains("session_already_available"));
            }
            other => panic!("expected ory error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_login_browser_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .create_login_browser_flow(&[("return_to", "http://return")], Some("cookie"))
            .await
            .unwrap();
        assert_eq!(resp.body["id"], "login-1");
        assert_eq!(resp.body["type"], "login");
        assert_eq!(resp.body["return_to"], "http://return");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .contains("ory_kratos_session=login")
        );
    }

    #[tokio::test]
    async fn create_registration_browser_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .create_registration_browser_flow(&[("return_to", "http://return")], Some("cookie"))
            .await
            .unwrap();
        assert_eq!(resp.body["id"], "registration-1");
        assert_eq!(resp.body["type"], "registration");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .contains("ory_kratos_session=registration")
        );
    }

    #[tokio::test]
    async fn create_settings_browser_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .create_settings_browser_flow(Some("http://return"), Some("cookie"))
            .await
            .unwrap();
        assert_eq!(resp.body["id"], "settings-1");
        assert_eq!(resp.body["type"], "settings");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .contains("ory_kratos_session=settings")
        );
    }

    #[tokio::test]
    async fn create_recovery_browser_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .create_recovery_browser_flow(Some("http://return"), Some("cookie"))
            .await
            .unwrap();
        assert_eq!(resp.body["id"], "recovery-1");
        assert_eq!(resp.body["type"], "recovery");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .contains("ory_kratos_session=recovery")
        );
    }

    #[tokio::test]
    async fn create_logout_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .create_logout_flow(Some("http://return"), Some("cookie"))
            .await
            .unwrap();
        assert_eq!(resp.body["id"], "logout-1");
        assert_eq!(resp.body["return_to"], "http://return");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(cookies[0].to_str().unwrap().contains("ory_kratos_session="));
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

    #[tokio::test]
    async fn submit_recovery_token_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .submit_recovery_token(
                "valid-recovery-token",
                "recovery-flow-id",
                Some("session=abc"),
                Some("csrf-1"),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.location,
            Some("https://ui.example.com/recovery?flow=recovery-flow-id".to_string())
        );
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 2);
        let cookie_strs: Vec<String> = cookies
            .iter()
            .map(|c| c.to_str().unwrap().to_string())
            .collect();
        assert!(cookie_strs.iter().any(|c| c.contains("ory_kratos_session")));
        assert!(cookie_strs.iter().any(|c| c.contains("csrf_token_1234")));
    }

    #[tokio::test]
    async fn submit_recovery_token_rejects_invalid_token() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let err = client
            .submit_recovery_token("invalid", "recovery-flow-id", None, None)
            .await
            .unwrap_err();
        match err {
            OryClientError::Ory { status, .. } => assert_eq!(status, 400),
            other => panic!("expected Ory error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn submit_verification_token_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .submit_verification_token(
                "valid-verification-token",
                "verification-flow-id",
                Some("session=xyz"),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            resp.location,
            Some("https://ui.example.com/verification?flow=session=xyz".to_string())
        );
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .contains("ory_kratos_session=verification")
        );
    }

    #[tokio::test]
    async fn submit_verification_token_rejects_invalid_token() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let err = client
            .submit_verification_token("invalid", "verification-flow-id", None, None)
            .await
            .unwrap_err();
        match err {
            OryClientError::Ory { status, .. } => assert_eq!(status, 400),
            other => panic!("expected Ory error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn admin_get_session_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new(&url).unwrap();
        let resp = client.admin_get_session("session-1").await.unwrap();
        assert_eq!(resp["id"], "session-1");
        assert_eq!(resp["active"], true);
    }

    #[tokio::test]
    async fn delete_session_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new(&url).unwrap();
        client.delete_session("session-1").await.unwrap();
    }

    #[tokio::test]
    async fn list_sessions_by_identity_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new(&url).unwrap();
        let resp = client
            .list_sessions_by_identity("identity-1")
            .await
            .unwrap();
        assert_eq!(resp["identity_id"], "identity-1");
        assert!(resp["sessions"].is_array());
    }

    #[tokio::test]
    async fn whoami_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client.whoami("token-1").await.unwrap();
        assert_eq!(resp["id"], "session-1");
        assert_eq!(resp["token"], "token-1");
    }

    #[tokio::test]
    async fn create_login_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client.create_login_flow(&[]).await.unwrap();
        assert_eq!(resp["id"], "login-1");
        assert_eq!(resp["type"], "login");
    }

    #[tokio::test]
    async fn create_registration_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .create_registration_flow(&[("return_to", "http://return")])
            .await
            .unwrap();
        assert_eq!(resp["id"], "registration-1");
        assert_eq!(resp["type"], "registration");
    }

    #[tokio::test]
    async fn get_registration_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .get_registration_flow("flow-1", Some("cookie"))
            .await
            .unwrap();
        assert_eq!(resp.body["id"], "flow-1");
        assert_eq!(resp.body["type"], "registration");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .contains("ory_kratos_session=registration")
        );
    }

    #[tokio::test]
    async fn get_settings_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .get_settings_flow("flow-1", Some("cookie"))
            .await
            .unwrap();
        assert_eq!(resp.body["id"], "flow-1");
        assert_eq!(resp.body["type"], "settings");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .contains("ory_kratos_session=settings")
        );
    }

    #[tokio::test]
    async fn get_recovery_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .get_recovery_flow("flow-1", Some("cookie"))
            .await
            .unwrap();
        assert_eq!(resp.body["id"], "flow-1");
        assert_eq!(resp.body["type"], "recovery");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .contains("ory_kratos_session=recovery")
        );
    }

    #[tokio::test]
    async fn get_verification_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .get_verification_flow("flow-1", Some("cookie"))
            .await
            .unwrap();
        assert_eq!(resp.body["id"], "flow-1");
        assert_eq!(resp.body["type"], "verification");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .contains("ory_kratos_session=verification")
        );
    }

    #[tokio::test]
    async fn submit_registration_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .submit_registration_flow("flow-1", Some("cookie"), json!({ "traits": {} }))
            .await
            .unwrap();
        assert_eq!(resp.body["id"], "flow-1");
        assert_eq!(resp.body["type"], "registration");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .contains("ory_kratos_session=registration")
        );
    }

    #[tokio::test]
    async fn submit_settings_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .submit_settings_flow("flow-1", Some("cookie"), json!({ "method": "password" }))
            .await
            .unwrap();
        assert_eq!(resp.body["id"], "flow-1");
        assert_eq!(resp.body["type"], "settings");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .contains("ory_kratos_session=settings")
        );
    }

    #[tokio::test]
    async fn submit_recovery_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .submit_recovery_flow(
                "flow-1",
                Some("cookie"),
                json!({ "email": "a@example.com" }),
            )
            .await
            .unwrap();
        assert_eq!(resp.body["id"], "flow-1");
        assert_eq!(resp.body["type"], "recovery");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .contains("ory_kratos_session=recovery")
        );
    }

    #[tokio::test]
    async fn submit_verification_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .submit_verification_flow(
                "flow-1",
                Some("cookie"),
                json!({ "email": "a@example.com" }),
            )
            .await
            .unwrap();
        assert_eq!(resp.body["id"], "flow-1");
        assert_eq!(resp.body["type"], "verification");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .contains("ory_kratos_session=verification")
        );
    }

    #[tokio::test]
    async fn create_verification_flow_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new_with_public(&url, &url).unwrap();
        let resp = client
            .create_verification_flow(Some("http://return"), Some("cookie"))
            .await
            .unwrap();
        assert_eq!(resp.body["id"], "verification-1");
        assert_eq!(resp.body["type"], "verification");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .contains("ory_kratos_session=verification")
        );
    }

    #[tokio::test]
    async fn whoami_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client.whoami("token-1").await.unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn create_login_flow_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client.create_login_flow(&[]).await.unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn create_registration_flow_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client.create_registration_flow(&[]).await.unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn to_session_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client.to_session(None, None).await.unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn get_login_flow_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client.get_login_flow("flow-1", None).await.unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn get_registration_flow_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client
            .get_registration_flow("flow-1", None)
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn get_settings_flow_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client.get_settings_flow("flow-1", None).await.unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn get_recovery_flow_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client.get_recovery_flow("flow-1", None).await.unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn get_verification_flow_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client
            .get_verification_flow("flow-1", None)
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn submit_login_flow_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client
            .submit_login_flow("flow-1", None, json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn submit_registration_flow_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client
            .submit_registration_flow("flow-1", None, json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn submit_settings_flow_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client
            .submit_settings_flow("flow-1", None, json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn submit_recovery_flow_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client
            .submit_recovery_flow("flow-1", None, json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn submit_verification_flow_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client
            .submit_verification_flow("flow-1", None, json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn create_logout_flow_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client.create_logout_flow(None, None).await.unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn submit_logout_flow_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client
            .submit_logout_flow("token-1", None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn create_verification_flow_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client
            .create_verification_flow(None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn create_login_browser_flow_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client
            .create_login_browser_flow(&[], None)
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn create_registration_browser_flow_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client
            .create_registration_browser_flow(&[], None)
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn create_settings_browser_flow_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client
            .create_settings_browser_flow(None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn create_recovery_browser_flow_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client
            .create_recovery_browser_flow(None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn get_flow_error_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client.get_flow_error("error-1").await.unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn get_webauthn_js_missing_public_url() {
        let client = KratosClient::new("http://example.com/").unwrap();
        let err = client.get_webauthn_js().await.unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn create_identity_error() {
        let app = Router::new().route("/admin/identities", post(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = KratosClient::new(&format!("http://{addr}")).unwrap();
        let err = client.create_identity(json!({})).await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn get_identity_error() {
        let app = Router::new().route("/admin/identities/{id}", get(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = KratosClient::new(&format!("http://{addr}")).unwrap();
        let err = client.get_identity("identity-1").await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn update_identity_error() {
        let app = Router::new().route("/admin/identities/{id}", put(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = KratosClient::new(&format!("http://{addr}")).unwrap();
        let err = client
            .update_identity("identity-1", json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn delete_identity_error() {
        let app = Router::new().route("/admin/identities/{id}", delete(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = KratosClient::new(&format!("http://{addr}")).unwrap();
        let err = client.delete_identity("identity-1").await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn get_identity_schema_error() {
        let app = Router::new().route("/schemas/{id}", get(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = KratosClient::new(&format!("http://{addr}")).unwrap();
        let err = client.get_identity_schema("default").await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn admin_get_session_error() {
        let app = Router::new().route("/admin/sessions/{id}", get(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = KratosClient::new(&format!("http://{addr}")).unwrap();
        let err = client.admin_get_session("session-1").await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn delete_session_error() {
        let app = Router::new().route("/admin/sessions/{id}", delete(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = KratosClient::new(&format!("http://{addr}")).unwrap();
        let err = client.delete_session("session-1").await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn whoami_error() {
        let app = Router::new().route("/sessions/whoami", get(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            KratosClient::new_with_public(&format!("http://{addr}"), &format!("http://{addr}"))
                .unwrap();
        let err = client.whoami("token-1").await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn create_login_flow_error() {
        let app = Router::new().route("/self-service/login/api", get(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            KratosClient::new_with_public(&format!("http://{addr}"), &format!("http://{addr}"))
                .unwrap();
        let err = client.create_login_flow(&[]).await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn create_logout_flow_error() {
        let app = Router::new().route("/self-service/logout/browser", get(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            KratosClient::new_with_public(&format!("http://{addr}"), &format!("http://{addr}"))
                .unwrap();
        let err = client.create_logout_flow(None, None).await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn submit_logout_flow_error() {
        let app = Router::new().route("/self-service/logout", get(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            KratosClient::new_with_public(&format!("http://{addr}"), &format!("http://{addr}"))
                .unwrap();
        let err = client
            .submit_logout_flow("token-1", None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn get_flow_error_error() {
        let app = Router::new().route("/self-service/errors", get(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            KratosClient::new_with_public(&format!("http://{addr}"), &format!("http://{addr}"))
                .unwrap();
        let err = client.get_flow_error("error-1").await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn get_webauthn_js_error() {
        let app = Router::new().route("/.well-known/ory/webauthn.js", get(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            KratosClient::new_with_public(&format!("http://{addr}"), &format!("http://{addr}"))
                .unwrap();
        let err = client.get_webauthn_js().await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn create_login_browser_flow_preserves_multiple_set_cookie_headers() {
        async fn multi_cookie_login() -> (axum::http::StatusCode, axum::http::HeaderMap, Json<Value>)
        {
            let mut headers = axum::http::HeaderMap::new();
            headers.append(
                "set-cookie",
                "ory_kratos_session=a; Path=/; HttpOnly".parse().unwrap(),
            );
            headers.append(
                "set-cookie",
                "ory_kratos_continuity=b; Path=/; HttpOnly".parse().unwrap(),
            );
            (
                axum::http::StatusCode::OK,
                headers,
                Json(json!({ "id": "login-1", "type": "login" })),
            )
        }

        let app = Router::new().route("/self-service/login/browser", get(multi_cookie_login));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client =
            KratosClient::new_with_public(&format!("http://{addr}"), &format!("http://{addr}"))
                .unwrap();
        let resp = client.create_login_browser_flow(&[], None).await.unwrap();
        assert_eq!(resp.body["id"], "login-1");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 2);
    }

    #[tokio::test]
    async fn new_with_invalid_url() {
        let err = KratosClient::new("not-a-url").unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn list_identities_by_identifier_found() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new(&url).unwrap();
        let resp = client
            .list_identities_by_identifier("tenant-1", "found@example.com")
            .await
            .unwrap();
        let identities = resp.as_array().unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0]["id"], "identity-found");
    }

    #[tokio::test]
    async fn list_identities_by_identifier_not_found() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new(&url).unwrap();
        let resp = client
            .list_identities_by_identifier("tenant-1", "missing@example.com")
            .await
            .unwrap();
        let identities = resp.as_array().unwrap();
        assert!(identities.is_empty());
    }

    #[tokio::test]
    async fn create_session_for_identity_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new(&url).unwrap();
        let resp = client
            .create_session_for_identity("identity-1", Some("oidc"))
            .await
            .unwrap();
        assert_eq!(resp.body["id"], "session-created");
        assert_eq!(resp.body["identity"]["id"], "identity-1");
        assert_eq!(resp.body["token"], true);
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .contains("ory_kratos_session=identity-1")
        );
    }

    #[tokio::test]
    async fn create_session_for_identity_error() {
        let app = Router::new().route("/admin/identities/{id}/sessions", post(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = KratosClient::new(&format!("http://{addr}")).unwrap();
        let err = client
            .create_session_for_identity("identity-1", None)
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn create_recovery_link_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new(&url).unwrap();
        let resp = client
            .create_recovery_link("identity-1", Some(3600))
            .await
            .unwrap();
        assert_eq!(resp.body["recovery_token"], "identity-1-recovery-token");
        assert!(
            resp.body["recovery_link"]
                .as_str()
                .unwrap()
                .contains("token=identity-1-recovery-token")
        );
    }

    #[tokio::test]
    async fn list_courier_messages_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KratosClient::new(&url).unwrap();
        let resp = client
            .list_courier_messages(Some("identity-1"), Some("verification"))
            .await
            .unwrap();
        let messages = resp.as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["id"], "message-1");
        let body = messages[0]["body"].as_str().unwrap();
        assert!(body.contains("verification?"));
        assert!(body.contains("flow=identity-1-verification-flow"));
        assert!(body.contains("token=identity-1-verify-token"));
    }
}
