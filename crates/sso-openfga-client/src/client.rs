use reqwest::{Client, Url};
use serde_json::Value;
use tracing::{debug, instrument};

use crate::error::OpenFgaClientError;

/// Internal client for OpenFGA.
#[derive(Debug, Clone)]
pub struct OpenFgaClient {
    client: Client,
    base_url: Url,
}

impl OpenFgaClient {
    /// Create a new OpenFGA client.
    pub fn new(base_url: &str) -> Result<Self, OpenFgaClientError> {
        Ok(Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .connect_timeout(std::time::Duration::from_secs(5))
                .build()?,
            base_url: parse_base_url(base_url)?,
        })
    }

    /// Create a new store.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn create_store(&self, name: &str) -> Result<String, OpenFgaClientError> {
        let url = self.base_url.join("stores")?;
        debug!(%url, %name, "creating openfga store");
        let response = self
            .client
            .post(url)
            .json(&serde_json::json!({ "name": name }))
            .send()
            .await
            .map_err(OpenFgaClientError::Http)?;

        handle_response(response)
            .await?
            .get("id")
            .and_then(|v| v.as_str().map(String::from))
            .ok_or_else(|| OpenFgaClientError::InvalidResponse("missing store id".into()))
    }

    /// List stores.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn list_stores(&self) -> Result<Value, OpenFgaClientError> {
        let url = self.base_url.join("stores")?;
        debug!(%url, "listing openfga stores");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(OpenFgaClientError::Http)?;
        handle_response(response).await
    }

    /// Get a store by id.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn get_store(&self, store_id: &str) -> Result<Value, OpenFgaClientError> {
        let url = self.base_url.join(&format!("stores/{store_id}"))?;
        debug!(%url, %store_id, "getting openfga store");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(OpenFgaClientError::Http)?;
        handle_response(response).await
    }

    /// Delete a store by id.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn delete_store(&self, store_id: &str) -> Result<(), OpenFgaClientError> {
        let url = self.base_url.join(&format!("stores/{store_id}"))?;
        debug!(%url, %store_id, "deleting openfga store");
        let response = self
            .client
            .delete(url)
            .send()
            .await
            .map_err(OpenFgaClientError::Http)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(openfga_error(response).await)
        }
    }

    /// Write an authorization model for a namespace.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn write_authorization_model(
        &self,
        store_id: &str,
        namespace: &str,
        relations: &[String],
    ) -> Result<String, OpenFgaClientError> {
        let url = self
            .base_url
            .join(&format!("stores/{store_id}/authorization-models"))?;
        debug!(%url, %store_id, %namespace, ?relations, "writing openfga authorization model");

        let type_definitions = build_namespace_model(namespace, relations);
        let payload = serde_json::json!({
            "schema_version": "1.1",
            "type_definitions": type_definitions,
        });

        let response = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(OpenFgaClientError::Http)?;

        handle_response(response)
            .await?
            .get("authorization_model_id")
            .and_then(|v| v.as_str().map(String::from))
            .ok_or_else(|| {
                OpenFgaClientError::InvalidResponse("missing authorization_model_id".into())
            })
    }

    /// List authorization models for a store.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn list_authorization_models(
        &self,
        store_id: &str,
    ) -> Result<Value, OpenFgaClientError> {
        let url = self
            .base_url
            .join(&format!("stores/{store_id}/authorization-models"))?;
        debug!(%url, %store_id, "listing openfga authorization models");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(OpenFgaClientError::Http)?;
        handle_response(response).await
    }

    /// Get an authorization model by id.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn get_authorization_model(
        &self,
        store_id: &str,
        model_id: &str,
    ) -> Result<Value, OpenFgaClientError> {
        let url = self.base_url.join(&format!(
            "stores/{store_id}/authorization-models/{model_id}"
        ))?;
        debug!(%url, %store_id, %model_id, "getting openfga authorization model");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(OpenFgaClientError::Http)?;
        handle_response(response).await
    }

    /// Write (create or delete) a relation tuple.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn write_tuple(
        &self,
        store_id: &str,
        model_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        user: &str,
        operation: WriteTupleOp,
    ) -> Result<(), OpenFgaClientError> {
        let url = self.base_url.join(&format!("stores/{store_id}/write"))?;
        debug!(%url, %store_id, %model_id, %namespace, %object, %relation, %user, ?operation, "writing openfga tuple");

        let tuple_key = serde_json::json!({
            "user": user,
            "relation": relation,
            "object": format!("{namespace}:{object}"),
        });

        let payload = match operation {
            WriteTupleOp::Insert => serde_json::json!({
                "writes": { "tuple_keys": [tuple_key] },
                "authorization_model_id": model_id,
            }),
            WriteTupleOp::Delete => serde_json::json!({
                "deletes": { "tuple_keys": [tuple_key] },
                "authorization_model_id": model_id,
            }),
        };

        let response = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(OpenFgaClientError::Http)?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(openfga_error(response).await)
        }
    }

    /// Check whether a user has a relation on an object.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn check(
        &self,
        store_id: &str,
        model_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        user: &str,
    ) -> Result<bool, OpenFgaClientError> {
        let url = self.base_url.join(&format!("stores/{store_id}/check"))?;
        debug!(%url, %store_id, %model_id, %namespace, %object, %relation, %user, "checking openfga permission");

        let payload = serde_json::json!({
            "tuple_key": {
                "user": user,
                "relation": relation,
                "object": format!("{namespace}:{object}"),
            },
            "authorization_model_id": model_id,
        });

        let response = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(OpenFgaClientError::Http)?;

        if response.status().is_success() {
            let body: Value = response.json().await.map_err(OpenFgaClientError::Http)?;
            Ok(body
                .get("allowed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false))
        } else {
            Err(openfga_error(response).await)
        }
    }

    /// Expand a relation for an object.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn expand(
        &self,
        store_id: &str,
        model_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
    ) -> Result<Value, OpenFgaClientError> {
        let url = self.base_url.join(&format!("stores/{store_id}/expand"))?;
        debug!(%url, %store_id, %model_id, %namespace, %object, %relation, "expanding openfga relation");

        let payload = serde_json::json!({
            "tuple_key": {
                "relation": relation,
                "object": format!("{namespace}:{object}"),
            },
            "authorization_model_id": model_id,
        });

        let response = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(OpenFgaClientError::Http)?;
        handle_response(response).await
    }

    /// List objects a user has a relation on.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn list_objects(
        &self,
        store_id: &str,
        model_id: &str,
        namespace: &str,
        relation: &str,
        user: &str,
    ) -> Result<Vec<String>, OpenFgaClientError> {
        let url = self
            .base_url
            .join(&format!("stores/{store_id}/list-objects"))?;
        debug!(%url, %store_id, %model_id, %namespace, %relation, %user, "listing openfga objects");

        let payload = serde_json::json!({
            "user": user,
            "relation": relation,
            "type": namespace,
            "authorization_model_id": model_id,
        });

        let response = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(OpenFgaClientError::Http)?;

        let body = handle_response(response).await?;
        let objects = body
            .get("objects")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Ok(objects)
    }
}

/// Operation for [`OpenFgaClient::write_tuple`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteTupleOp {
    /// Insert the tuple.
    Insert,
    /// Delete the tuple.
    Delete,
}

fn parse_base_url(url: &str) -> Result<Url, OpenFgaClientError> {
    let mut url =
        Url::parse(url).map_err(|e| OpenFgaClientError::InvalidResponse(e.to_string()))?;
    if !url.path().ends_with('/')
        && let Ok(mut path) = url.path_segments_mut()
    {
        path.push("");
    }
    Ok(url)
}

async fn handle_response(response: reqwest::Response) -> Result<Value, OpenFgaClientError> {
    if response.status().is_success() {
        response.json().await.map_err(OpenFgaClientError::Http)
    } else {
        Err(openfga_error(response).await)
    }
}

async fn openfga_error(response: reqwest::Response) -> OpenFgaClientError {
    let status = response.status().as_u16();
    let message = response
        .text()
        .await
        .unwrap_or_else(|_| "<unreadable body>".to_string());
    OpenFgaClientError::OpenFga { status, message }
}

fn build_namespace_model(namespace: &str, relations: &[String]) -> Vec<Value> {
    let mut type_definitions = vec![serde_json::json!({ "type": "user" })];

    let mut relation_map = serde_json::Map::new();
    let mut relation_metadata = serde_json::Map::new();
    for relation in relations {
        relation_map.insert(relation.clone(), serde_json::json!({ "this": {} }));
        relation_metadata.insert(
            relation.clone(),
            serde_json::json!({
                "directly_related_user_types": [{ "type": "user" }]
            }),
        );
    }

    type_definitions.push(serde_json::json!({
        "type": namespace,
        "relations": relation_map,
        "metadata": {
            "relations": relation_metadata,
        },
    }));

    type_definitions
}

#[cfg(test)]
mod tests {
    use axum::{
        Json, Router,
        extract::{Path, State},
        http::StatusCode,
        routing::{get, post},
    };
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    struct FakeState {
        stores: Arc<Mutex<Vec<Value>>>,
        models: Arc<Mutex<Vec<Value>>>,
        tuples: Arc<Mutex<Vec<Value>>>,
    }

    fn app(state: FakeState) -> Router {
        Router::new()
            .route("/stores", post(create_store).get(list_stores))
            .route("/stores/{store_id}", get(get_store).delete(delete_store))
            .route(
                "/stores/{store_id}/authorization-models",
                post(write_model).get(list_models),
            )
            .route(
                "/stores/{store_id}/authorization-models/{model_id}",
                get(get_model),
            )
            .route("/stores/{store_id}/write", post(write_tuple))
            .route("/stores/{store_id}/check", post(check))
            .route("/stores/{store_id}/expand", post(expand))
            .route("/stores/{store_id}/list-objects", post(list_objects))
            .with_state(state)
    }

    async fn create_store(State(state): State<FakeState>, Json(body): Json<Value>) -> Json<Value> {
        let id = format!("store-{}", state.stores.lock().unwrap().len());
        let store = json!({ "id": id, "name": body["name"] });
        state.stores.lock().unwrap().push(store.clone());
        Json(store)
    }

    async fn list_stores(State(state): State<FakeState>) -> Json<Value> {
        let stores = state.stores.lock().unwrap().clone();
        Json(json!({ "stores": stores }))
    }

    async fn get_store(
        State(state): State<FakeState>,
        Path(store_id): Path<String>,
    ) -> Json<Value> {
        let stores = state.stores.lock().unwrap();
        let store = stores
            .iter()
            .find(|s| s.get("id").and_then(|v| v.as_str()) == Some(&store_id))
            .cloned()
            .unwrap_or_else(|| json!({ "id": store_id, "name": "unknown" }));
        Json(store)
    }

    async fn delete_store(
        State(state): State<FakeState>,
        Path(store_id): Path<String>,
    ) -> StatusCode {
        let mut stores = state.stores.lock().unwrap();
        stores.retain(|s| s.get("id").and_then(|v| v.as_str()) != Some(&store_id));
        StatusCode::NO_CONTENT
    }

    async fn write_model(
        State(state): State<FakeState>,
        Path(store_id): Path<String>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let model_id = format!("model-{}", state.models.lock().unwrap().len());
        let model = json!({
            "authorization_model_id": model_id,
            "store_id": store_id,
            "schema_version": body["schema_version"],
            "type_definitions": body["type_definitions"],
        });
        state.models.lock().unwrap().push(model.clone());
        Json(json!({ "authorization_model_id": model_id }))
    }

    async fn list_models(State(state): State<FakeState>) -> Json<Value> {
        let models = state.models.lock().unwrap().clone();
        Json(json!({ "authorization_models": models }))
    }

    async fn get_model(
        State(state): State<FakeState>,
        Path((_, model_id)): Path<(String, String)>,
    ) -> Json<Value> {
        let models = state.models.lock().unwrap();
        let model = models
            .iter()
            .find(|m| m.get("authorization_model_id").and_then(|v| v.as_str()) == Some(&model_id))
            .cloned()
            .unwrap_or_default();
        Json(model)
    }

    async fn write_tuple(
        State(state): State<FakeState>,
        Path(store_id): Path<String>,
        Json(body): Json<Value>,
    ) -> StatusCode {
        if let Some(writes) = body.get("writes").and_then(|w| w.get("tuple_keys")) {
            for tuple in writes.as_array().unwrap_or(&vec![]) {
                let mut t = tuple.clone();
                t["store_id"] = json!(store_id);
                state.tuples.lock().unwrap().push(t);
            }
        }
        if let Some(deletes) = body.get("deletes").and_then(|d| d.get("tuple_keys")) {
            let keys = deletes.as_array().unwrap_or(&vec![]).clone();
            let mut tuples = state.tuples.lock().unwrap();
            for key in keys {
                tuples.retain(|t| {
                    t.get("user") != key.get("user")
                        || t.get("relation") != key.get("relation")
                        || t.get("object") != key.get("object")
                });
            }
        }
        StatusCode::OK
    }

    async fn check(
        State(state): State<FakeState>,
        Path(store_id): Path<String>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let key = body.get("tuple_key").cloned().unwrap_or_default();
        let user = key.get("user").and_then(|v| v.as_str()).unwrap_or("");
        let relation = key.get("relation").and_then(|v| v.as_str()).unwrap_or("");
        let object = key.get("object").and_then(|v| v.as_str()).unwrap_or("");
        let allowed = state.tuples.lock().unwrap().iter().any(|t| {
            t.get("store_id").and_then(|v| v.as_str()) == Some(&store_id)
                && t.get("user").and_then(|v| v.as_str()) == Some(user)
                && t.get("relation").and_then(|v| v.as_str()) == Some(relation)
                && t.get("object").and_then(|v| v.as_str()) == Some(object)
        });
        Json(json!({ "allowed": allowed }))
    }

    async fn expand(Json(_): Json<Value>) -> Json<Value> {
        Json(json!({ "tree": { "root": {} } }))
    }

    async fn list_objects(
        State(state): State<FakeState>,
        Path(store_id): Path<String>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let user = body.get("user").and_then(|v| v.as_str()).unwrap_or("");
        let relation = body.get("relation").and_then(|v| v.as_str()).unwrap_or("");
        let objects: Vec<String> = state
            .tuples
            .lock()
            .unwrap()
            .iter()
            .filter(|t| {
                t.get("store_id").and_then(|v| v.as_str()) == Some(&store_id)
                    && t.get("user").and_then(|v| v.as_str()) == Some(user)
                    && t.get("relation").and_then(|v| v.as_str()) == Some(relation)
            })
            .filter_map(|t| t.get("object").and_then(|v| v.as_str()).map(String::from))
            .collect();
        Json(json!({ "objects": objects }))
    }

    async fn start_server() -> (tokio::task::JoinHandle<()>, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = FakeState::default();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app(state)).await.unwrap();
        });
        (handle, format!("http://{addr}"))
    }

    #[tokio::test]
    async fn store_lifecycle_round_trip() {
        let (_handle, url) = start_server().await;
        let client = OpenFgaClient::new(&url).unwrap();

        let store_id = client.create_store("test-store").await.unwrap();
        assert!(store_id.starts_with("store-"));

        let store = client.get_store(&store_id).await.unwrap();
        assert_eq!(store["id"], store_id);

        let stores = client.list_stores().await.unwrap();
        let store_list = stores["stores"].as_array().unwrap();
        assert_eq!(store_list.len(), 1);

        client.delete_store(&store_id).await.unwrap();
        let stores = client.list_stores().await.unwrap();
        assert!(stores["stores"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn model_and_tuple_round_trip() {
        let (_handle, url) = start_server().await;
        let client = OpenFgaClient::new(&url).unwrap();

        let store_id = client.create_store("test-store").await.unwrap();
        let model_id = client
            .write_authorization_model(&store_id, "document", &["reader".into(), "writer".into()])
            .await
            .unwrap();
        assert!(model_id.starts_with("model-"));

        let model = client
            .get_authorization_model(&store_id, &model_id)
            .await
            .unwrap();
        assert_eq!(model["authorization_model_id"], model_id);

        let allowed = client
            .check(
                &store_id,
                &model_id,
                "document",
                "doc-1",
                "reader",
                "user:alice",
            )
            .await
            .unwrap();
        assert!(!allowed);

        client
            .write_tuple(
                &store_id,
                &model_id,
                "document",
                "doc-1",
                "reader",
                "user:alice",
                WriteTupleOp::Insert,
            )
            .await
            .unwrap();

        let allowed = client
            .check(
                &store_id,
                &model_id,
                "document",
                "doc-1",
                "reader",
                "user:alice",
            )
            .await
            .unwrap();
        assert!(allowed);

        let objects = client
            .list_objects(&store_id, &model_id, "document", "reader", "user:alice")
            .await
            .unwrap();
        assert_eq!(objects, vec!["document:doc-1"]);

        client
            .write_tuple(
                &store_id,
                &model_id,
                "document",
                "doc-1",
                "reader",
                "user:alice",
                WriteTupleOp::Delete,
            )
            .await
            .unwrap();

        let allowed = client
            .check(
                &store_id,
                &model_id,
                "document",
                "doc-1",
                "reader",
                "user:alice",
            )
            .await
            .unwrap();
        assert!(!allowed);
    }

    #[tokio::test]
    async fn expand_returns_value() {
        let (_handle, url) = start_server().await;
        let client = OpenFgaClient::new(&url).unwrap();

        let store_id = client.create_store("test-store").await.unwrap();
        let model_id = client
            .write_authorization_model(&store_id, "document", &["reader".into()])
            .await
            .unwrap();

        let expanded = client
            .expand(&store_id, &model_id, "document", "doc-1", "reader")
            .await
            .unwrap();
        assert!(expanded.get("tree").is_some());
    }

    #[tokio::test]
    async fn new_with_invalid_url() {
        let err = OpenFgaClient::new("not-a-url").unwrap_err();
        assert!(matches!(err, OpenFgaClientError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn openfga_error_maps_to_error() {
        let app = Router::new().route("/stores", post(|| async { StatusCode::BAD_REQUEST }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = OpenFgaClient::new(&format!("http://{addr}")).unwrap();
        let err = client.create_store("x").await.unwrap_err();
        assert!(matches!(
            err,
            OpenFgaClientError::OpenFga { status: 400, .. }
        ));
    }
}
