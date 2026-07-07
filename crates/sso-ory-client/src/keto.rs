use reqwest::{Client, Url};
use serde_json::Value;
use tracing::{debug, instrument};

use crate::error::OryClientError;

/// Internal client for Ory Keto (read and write endpoints).
#[derive(Debug, Clone)]
pub struct KetoClient {
    client: Client,
    read_url: Url,
    write_url: Url,
}

impl KetoClient {
    /// Create a new Keto client.
    pub fn new(read_url: &str, write_url: &str) -> Result<Self, OryClientError> {
        Ok(Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .connect_timeout(std::time::Duration::from_secs(5))
                .build()?,
            read_url: parse_base_url(read_url)?,
            write_url: parse_base_url(write_url)?,
        })
    }

    /// Check whether a subject has a relation on an object.
    #[instrument(skip(self), fields(read_url = %self.read_url))]
    pub async fn check_permission(
        &self,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<bool, OryClientError> {
        let url = self.read_url.join("relation-tuples/check")?;
        debug!(%url, %namespace, %object, %relation, "checking keto permission");
        let response = self
            .client
            .get(url)
            .query(&[
                ("namespace", namespace),
                ("object", object),
                ("relation", relation),
                ("subject_id", subject_id),
            ])
            .send()
            .await
            .map_err(OryClientError::Http)?;

        let status = response.status();
        if status.is_success() {
            let body: Value = response.json().await.map_err(OryClientError::Http)?;
            Ok(body
                .get("allowed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false))
        } else if status.as_u16() == 403 {
            // Keto returns 403 when the permission is denied.
            Ok(false)
        } else {
            Err(ory_error(response).await)
        }
    }

    /// Create a relation tuple.
    #[instrument(skip(self), fields(write_url = %self.write_url))]
    pub async fn create_relation_tuple(
        &self,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<Value, OryClientError> {
        let url = self.write_url.join("admin/relation-tuples")?;
        debug!(%url, %namespace, %object, %relation, "creating keto relation tuple");
        let payload = serde_json::json!({
            "namespace": namespace,
            "object": object,
            "relation": relation,
            "subject_id": subject_id,
        });
        let patch = serde_json::json!([{
            "action": "insert",
            "relation_tuple": payload,
        }]);
        let response = self
            .client
            .patch(url)
            .header("accept", "application/json")
            .json(&patch)
            .send()
            .await
            .map_err(OryClientError::Http)?;
        if response.status().is_success() {
            Ok(payload)
        } else {
            Err(ory_error(response).await)
        }
    }

    /// Delete a relation tuple.
    #[instrument(skip(self), fields(write_url = %self.write_url))]
    pub async fn delete_relation_tuple(
        &self,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<(), OryClientError> {
        let url = self.write_url.join("admin/relation-tuples")?;
        debug!(%url, %namespace, %object, %relation, "deleting keto relation tuple");
        let response = self
            .client
            .delete(url)
            .query(&[
                ("namespace", namespace),
                ("object", object),
                ("relation", relation),
                ("subject_id", subject_id),
            ])
            .send()
            .await
            .map_err(OryClientError::Http)?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(ory_error(response).await)
        }
    }

    /// Expand a subject set.
    #[instrument(skip(self), fields(read_url = %self.read_url))]
    pub async fn expand(
        &self,
        namespace: &str,
        object: &str,
        relation: &str,
    ) -> Result<Value, OryClientError> {
        let url = self.read_url.join("relation-tuples/expand")?;
        debug!(%url, %namespace, %object, %relation, "expanding keto subject set");
        let response = self
            .client
            .get(url)
            .query(&[
                ("namespace", namespace),
                ("object", object),
                ("relation", relation),
            ])
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response(response).await
    }

    /// Expand the objects a subject has a relation on.
    #[instrument(skip(self), fields(read_url = %self.read_url))]
    pub async fn expand_objects(
        &self,
        namespace: &str,
        relation: &str,
        query: &ExpandObjectsQuery<'_>,
    ) -> Result<Value, OryClientError> {
        let url = self.read_url.join("relation-tuples")?;
        debug!(%url, %namespace, %relation, "expanding keto objects");
        let mut params: Vec<(&str, String)> = vec![
            ("namespace", namespace.to_string()),
            ("relation", relation.to_string()),
        ];
        if let Some(subject_id) = query.subject_id {
            params.push(("subject_id", subject_id.to_string()));
        }
        if let Some(namespace) = query.subject_set_namespace {
            params.push(("subject_set.namespace", namespace.to_string()));
        }
        if let Some(object) = query.subject_set_object {
            params.push(("subject_set.object", object.to_string()));
        }
        if let Some(relation) = query.subject_set_relation {
            params.push(("subject_set.relation", relation.to_string()));
        }
        if let Some(max_depth) = query.max_depth {
            params.push(("max-depth", max_depth.to_string()));
        }
        let response = self
            .client
            .get(url)
            .query(&params)
            .send()
            .await
            .map_err(OryClientError::Http)?;
        handle_response(response).await
    }
}

/// Query parameters for [`KetoClient::expand_objects`].
#[derive(Debug, Clone, Default)]
pub struct ExpandObjectsQuery<'a> {
    /// Direct subject identifier.
    pub subject_id: Option<&'a str>,
    /// Namespace of a subject set.
    pub subject_set_namespace: Option<&'a str>,
    /// Object of a subject set.
    pub subject_set_object: Option<&'a str>,
    /// Relation of a subject set.
    pub subject_set_relation: Option<&'a str>,
    /// Maximum depth to traverse.
    pub max_depth: Option<i32>,
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
        extract::Query,
        routing::{delete, get, patch},
    };
    use serde_json::json;

    use super::*;

    fn app() -> Router {
        Router::new()
            .route("/relation-tuples/check", get(check_permission))
            .route("/relation-tuples/expand", get(expand))
            .route("/relation-tuples", get(expand_objects))
            .route(
                "/admin/relation-tuples",
                patch(create_tuple).delete(delete_tuple),
            )
    }

    async fn check_permission(Query(params): Query<HashMap<String, String>>) -> Json<Value> {
        let allowed = params.get("subject_id") == Some(&"alice".to_string());
        Json(json!({ "allowed": allowed }))
    }

    async fn expand() -> Json<Value> {
        Json(json!({ "children": [] }))
    }

    async fn expand_objects(Query(params): Query<HashMap<String, String>>) -> Json<Value> {
        let namespace = params.get("namespace").cloned().unwrap_or_default();
        let relation = params.get("relation").cloned().unwrap_or_default();
        let subject_id = params.get("subject_id").cloned().unwrap_or_default();
        let subject_set_namespace = params
            .get("subject_set.namespace")
            .cloned()
            .unwrap_or_default();
        let subject_set_object = params.get("subject_set.object").cloned().unwrap_or_default();
        let subject_set_relation = params
            .get("subject_set.relation")
            .cloned()
            .unwrap_or_default();

        let tuples = if !subject_id.is_empty() {
            vec![
                json!({
                    "namespace": namespace,
                    "object": "doc-1",
                    "relation": relation,
                    "subject_id": subject_id,
                }),
                json!({
                    "namespace": namespace,
                    "object": "doc-2",
                    "relation": relation,
                    "subject_id": subject_id,
                }),
            ]
        } else if !subject_set_namespace.is_empty()
            && !subject_set_object.is_empty()
            && !subject_set_relation.is_empty()
        {
            vec![json!({
                "namespace": namespace,
                "object": "doc-3",
                "relation": relation,
                "subject_set": {
                    "namespace": subject_set_namespace,
                    "object": subject_set_object,
                    "relation": subject_set_relation,
                },
            })]
        } else {
            vec![]
        };

        Json(json!({ "relation_tuples": tuples }))
    }

    async fn create_tuple(Json(body): Json<Value>) -> Json<Value> {
        body.as_array()
            .and_then(|deltas| deltas.first())
            .and_then(|delta| delta.get("relation_tuple"))
            .cloned()
            .unwrap_or_default()
            .into()
    }

    async fn delete_tuple() -> axum::http::StatusCode {
        axum::http::StatusCode::NO_CONTENT
    }

    async fn error_handler() -> (axum::http::StatusCode, &'static str) {
        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "error")
    }

    async fn forbidden_handler() -> axum::http::StatusCode {
        axum::http::StatusCode::FORBIDDEN
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
    async fn check_permission_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KetoClient::new(&url, &url).unwrap();
        assert!(
            client
                .check_permission("app", "doc-1", "read", "alice")
                .await
                .unwrap()
        );
        assert!(
            !client
                .check_permission("app", "doc-1", "read", "bob")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn create_and_delete_relation_tuple_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KetoClient::new(&url, &url).unwrap();
        let tuple = client
            .create_relation_tuple("app", "doc-1", "read", "alice")
            .await
            .unwrap();
        assert_eq!(tuple["namespace"], "app");
        assert_eq!(tuple["object"], "doc-1");
        client
            .delete_relation_tuple("app", "doc-1", "read", "alice")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn expand_round_trip() {
        let (_handle, url) = start_server().await;
        let client = KetoClient::new(&url, &url).unwrap();
        let resp = client.expand("app", "doc-1", "read").await.unwrap();
        assert!(resp["children"].is_array());
    }

    #[tokio::test]
    async fn check_permission_denied() {
        let app = Router::new().route("/relation-tuples/check", get(forbidden_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = KetoClient::new(&format!("http://{addr}"), &format!("http://{addr}")).unwrap();
        assert!(
            !client
                .check_permission("app", "doc-1", "read", "alice")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn check_permission_error() {
        let app = Router::new().route("/relation-tuples/check", get(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = KetoClient::new(&format!("http://{addr}"), &format!("http://{addr}")).unwrap();
        let err = client
            .check_permission("app", "doc-1", "read", "alice")
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn create_relation_tuple_error() {
        let app = Router::new().route("/admin/relation-tuples", patch(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = KetoClient::new(&format!("http://{addr}"), &format!("http://{addr}")).unwrap();
        let err = client
            .create_relation_tuple("app", "doc-1", "read", "alice")
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn delete_relation_tuple_error() {
        let app = Router::new().route("/admin/relation-tuples", delete(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = KetoClient::new(&format!("http://{addr}"), &format!("http://{addr}")).unwrap();
        let err = client
            .delete_relation_tuple("app", "doc-1", "read", "alice")
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn expand_error() {
        let app = Router::new().route("/relation-tuples/expand", get(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = KetoClient::new(&format!("http://{addr}"), &format!("http://{addr}")).unwrap();
        let err = client.expand("app", "doc-1", "read").await.unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn expand_objects_round_trip_with_subject_id() {
        let (_handle, url) = start_server().await;
        let client = KetoClient::new(&url, &url).unwrap();
        let resp = client
            .expand_objects(
                "app",
                "read",
                &ExpandObjectsQuery {
                    subject_id: Some("alice"),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let tuples = resp["relation_tuples"].as_array().unwrap();
        assert_eq!(tuples.len(), 2);
        assert_eq!(tuples[0]["object"], "doc-1");
        assert_eq!(tuples[1]["object"], "doc-2");
    }

    #[tokio::test]
    async fn expand_objects_round_trip_with_subject_set() {
        let (_handle, url) = start_server().await;
        let client = KetoClient::new(&url, &url).unwrap();
        let resp = client
            .expand_objects(
                "app",
                "read",
                &ExpandObjectsQuery {
                    subject_set_namespace: Some("Group"),
                    subject_set_object: Some("admins"),
                    subject_set_relation: Some("member"),
                    max_depth: Some(5),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let tuples = resp["relation_tuples"].as_array().unwrap();
        assert_eq!(tuples.len(), 1);
        assert_eq!(tuples[0]["object"], "doc-3");
    }

    #[tokio::test]
    async fn expand_objects_error() {
        let app = Router::new().route("/relation-tuples", get(error_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = KetoClient::new(&format!("http://{addr}"), &format!("http://{addr}")).unwrap();
        let err = client
            .expand_objects(
                "app",
                "read",
                &ExpandObjectsQuery {
                    subject_id: Some("alice"),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::Ory { status: 500, .. }));
    }

    #[tokio::test]
    async fn new_with_invalid_url() {
        let err = KetoClient::new("not-a-url", "http://example.com/").unwrap_err();
        assert!(matches!(err, OryClientError::InvalidResponse(_)));
    }
}
