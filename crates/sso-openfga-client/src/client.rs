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

    /// Find a store by name, returning its id.
    ///
    /// Paginates the store list because OpenFGA store names are not unique
    /// and there is no server-side name filter; the first match wins.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn find_store_by_name(&self, name: &str) -> Result<Option<String>, OpenFgaClientError> {
        let url = self.base_url.join("stores")?;
        let mut continuation_token = String::new();
        loop {
            let mut params: Vec<(&str, String)> = vec![("page_size", "100".to_string())];
            if !continuation_token.is_empty() {
                params.push(("continuation_token", continuation_token.clone()));
            }
            debug!(%url, %name, "searching openfga stores by name");
            let response = self
                .client
                .get(url.clone())
                .query(&params)
                .send()
                .await
                .map_err(OpenFgaClientError::Http)?;
            let body = handle_response(response).await?;
            if let Some(stores) = body.get("stores").and_then(|v| v.as_array()) {
                for store in stores {
                    let store_name = store.get("name").and_then(|v| v.as_str());
                    if store_name == Some(name)
                        && let Some(id) = store.get("id").and_then(|v| v.as_str())
                    {
                        return Ok(Some(id.to_string()));
                    }
                }
            }
            match body.get("continuation_token").and_then(|v| v.as_str()) {
                Some(token) if !token.is_empty() => continuation_token = token.to_string(),
                _ => return Ok(None),
            }
        }
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
        let model = flat_model(namespace, relations);
        self.write_model(store_id, &model).await
    }

    /// Write a raw authorization model.
    ///
    /// The model is passed through verbatim: `schema_version`,
    /// `type_definitions`, and optional `conditions`.
    #[instrument(skip(self, model), fields(base_url = %self.base_url))]
    pub async fn write_model(
        &self,
        store_id: &str,
        model: &Value,
    ) -> Result<String, OpenFgaClientError> {
        let url = self
            .base_url
            .join(&format!("stores/{store_id}/authorization-models"))?;
        debug!(%url, %store_id, "writing openfga authorization model");

        let response = self
            .client
            .post(url)
            .json(model)
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
        let key = TupleKey {
            user: user.to_string(),
            relation: relation.to_string(),
            object: format!("{namespace}:{object}"),
            condition_name: None,
            condition_context: None,
        };
        match operation {
            WriteTupleOp::Insert => self.write_tuples(store_id, model_id, &[key], &[]).await,
            WriteTupleOp::Delete => self.write_tuples(store_id, model_id, &[], &[key]).await,
        }
    }

    /// Write (create and/or delete) a batch of relation tuples.
    ///
    /// OpenFGA accepts at most 100 tuple keys per direction in a single call;
    /// callers are responsible for staying below that limit. Empty directions
    /// are omitted from the payload.
    #[instrument(skip(self, writes, deletes), fields(base_url = %self.base_url))]
    pub async fn write_tuples(
        &self,
        store_id: &str,
        model_id: &str,
        writes: &[TupleKey],
        deletes: &[TupleKey],
    ) -> Result<(), OpenFgaClientError> {
        if writes.is_empty() && deletes.is_empty() {
            return Ok(());
        }
        let url = self.base_url.join(&format!("stores/{store_id}/write"))?;
        debug!(%url, %store_id, %model_id, writes = writes.len(), deletes = deletes.len(), "writing openfga tuples");

        let mut payload = serde_json::json!({ "authorization_model_id": model_id });
        if !writes.is_empty() {
            payload["writes"] = serde_json::json!({
                "tuple_keys": writes.iter().map(TupleKey::to_write_json).collect::<Vec<_>>(),
            });
        }
        if !deletes.is_empty() {
            payload["deletes"] = serde_json::json!({
                "tuple_keys": deletes.iter().map(TupleKey::to_delete_json).collect::<Vec<_>>(),
            });
        }

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

    /// Read tuples matching a tuple key filter.
    ///
    /// The filter fields are matched exactly; passing a fully specified key
    /// (object, relation, and user) therefore yields at most one tuple.
    /// Condition data is not returned by the read endpoint, so the returned
    /// keys always carry `None` condition fields.
    #[instrument(skip(self, key), fields(base_url = %self.base_url))]
    pub async fn read_tuples(
        &self,
        store_id: &str,
        key: &TupleKey,
    ) -> Result<Vec<TupleKey>, OpenFgaClientError> {
        let url = self.base_url.join(&format!("stores/{store_id}/read"))?;
        debug!(%url, %store_id, "reading openfga tuples");

        let mut continuation_token = String::new();
        let mut tuples = Vec::new();
        loop {
            let mut payload = serde_json::json!({
                "tuple_key": {
                    "user": key.user,
                    "relation": key.relation,
                    "object": key.object,
                },
                "page_size": 100,
            });
            if !continuation_token.is_empty() {
                payload["continuation_token"] = Value::String(continuation_token.clone());
            }

            let response = self
                .client
                .post(url.clone())
                .json(&payload)
                .send()
                .await
                .map_err(OpenFgaClientError::Http)?;
            let body = handle_response(response).await?;

            if let Some(entries) = body.get("tuples").and_then(|v| v.as_array()) {
                for entry in entries {
                    let Some(key) = entry.get("key") else {
                        continue;
                    };
                    let user = match key.get("user").and_then(|v| v.as_str()) {
                        Some(user) => user.to_string(),
                        None => continue,
                    };
                    let relation = match key.get("relation").and_then(|v| v.as_str()) {
                        Some(relation) => relation.to_string(),
                        None => continue,
                    };
                    let object = match key.get("object").and_then(|v| v.as_str()) {
                        Some(object) => object.to_string(),
                        None => continue,
                    };
                    tuples.push(TupleKey {
                        user,
                        relation,
                        object,
                        condition_name: None,
                        condition_context: None,
                    });
                }
            }

            match body.get("continuation_token").and_then(|v| v.as_str()) {
                Some(token) if !token.is_empty() => continuation_token = token.to_string(),
                _ => return Ok(tuples),
            }
        }
    }

    /// Check whether a user has a relation on an object.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(self, opts), fields(base_url = %self.base_url))]
    pub async fn check(
        &self,
        store_id: &str,
        model_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        user: &str,
        opts: &RequestOptions,
    ) -> Result<bool, OpenFgaClientError> {
        let url = self.base_url.join(&format!("stores/{store_id}/check"))?;
        debug!(%url, %store_id, %model_id, %namespace, %object, %relation, %user, "checking openfga permission");

        let mut payload = serde_json::json!({
            "tuple_key": {
                "user": user,
                "relation": relation,
                "object": format!("{namespace}:{object}"),
            },
            "authorization_model_id": model_id,
        });
        opts.apply(&mut payload);

        let response = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(OpenFgaClientError::Http)?;

        if response.status().is_success() {
            let body: Value = response.json().await.map_err(OpenFgaClientError::Http)?;
            Ok(matches!(
                body.get("allowed").and_then(|v| v.as_bool()),
                Some(true)
            ))
        } else {
            Err(openfga_error(response).await)
        }
    }

    /// Expand a relation for an object.
    #[instrument(skip(self, opts), fields(base_url = %self.base_url))]
    pub async fn expand(
        &self,
        store_id: &str,
        model_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        opts: &RequestOptions,
    ) -> Result<Value, OpenFgaClientError> {
        let url = self.base_url.join(&format!("stores/{store_id}/expand"))?;
        debug!(%url, %store_id, %model_id, %namespace, %object, %relation, "expanding openfga relation");

        let mut payload = serde_json::json!({
            "tuple_key": {
                "relation": relation,
                "object": format!("{namespace}:{object}"),
            },
            "authorization_model_id": model_id,
        });
        opts.apply(&mut payload);

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
    #[instrument(skip(self, opts), fields(base_url = %self.base_url))]
    pub async fn list_objects(
        &self,
        store_id: &str,
        model_id: &str,
        namespace: &str,
        relation: &str,
        user: &str,
        opts: &RequestOptions,
    ) -> Result<Vec<String>, OpenFgaClientError> {
        let url = self
            .base_url
            .join(&format!("stores/{store_id}/list-objects"))?;
        debug!(%url, %store_id, %model_id, %namespace, %relation, %user, "listing openfga objects");

        let mut payload = serde_json::json!({
            "user": user,
            "relation": relation,
            "type": namespace,
            "authorization_model_id": model_id,
        });
        opts.apply(&mut payload);

        let response = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(OpenFgaClientError::Http)?;

        let body = handle_response(response).await?;
        let objects = match body.get("objects").and_then(|v| v.as_array()) {
            Some(arr) => arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            None => Vec::new(),
        };
        Ok(objects)
    }

    /// List users that have a relation on an object.
    ///
    /// Returns canonical subject strings: `type:id`, `type:id#relation`, or
    /// `type:*` for typed wildcards.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(self, opts), fields(base_url = %self.base_url))]
    pub async fn list_users(
        &self,
        store_id: &str,
        model_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        user_type_filters: &[String],
        opts: &RequestOptions,
    ) -> Result<Vec<String>, OpenFgaClientError> {
        let url = self
            .base_url
            .join(&format!("stores/{store_id}/list-users"))?;
        debug!(%url, %store_id, %model_id, %namespace, %object, %relation, "listing openfga users");

        let filters: Vec<Value> = user_type_filters
            .iter()
            .map(|f| match f.split_once('#') {
                Some((ty, rel)) => serde_json::json!({ "type": ty, "relation": rel }),
                None => serde_json::json!({ "type": f }),
            })
            .collect();

        let mut payload = serde_json::json!({
            "object": { "type": namespace, "id": object },
            "relation": relation,
            "user_filters": filters,
            "authorization_model_id": model_id,
        });
        opts.apply(&mut payload);

        let response = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(OpenFgaClientError::Http)?;

        let body = handle_response(response).await?;
        let users = match body.get("users").and_then(|v| v.as_array()) {
            Some(arr) => arr.iter().map(canonical_user).collect(),
            None => Vec::new(),
        };
        Ok(users)
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

/// A single OpenFGA tuple key.
///
/// `object` and `user` must already be typed (`type:id`, usersets
/// `type:id#relation`, or wildcards `type:*`).
#[derive(Debug, Clone, PartialEq)]
pub struct TupleKey {
    /// Typed subject, e.g. `user:anne` or `team:eng#member`.
    pub user: String,
    /// Relation name.
    pub relation: String,
    /// Typed object, e.g. `document:1`.
    pub object: String,
    /// Optional OpenFGA condition name (writes only).
    pub condition_name: Option<String>,
    /// Optional condition context (writes only).
    pub condition_context: Option<Value>,
}

impl TupleKey {
    fn to_write_json(&self) -> Value {
        let mut key = serde_json::json!({
            "user": self.user,
            "relation": self.relation,
            "object": self.object,
        });
        if let Some(name) = &self.condition_name {
            key["condition"] = serde_json::json!({
                "name": name,
                "context": match &self.condition_context {
                    Some(ctx) => ctx.clone(),
                    None => Value::Null,
                },
            });
        }
        key
    }

    fn to_delete_json(&self) -> Value {
        serde_json::json!({
            "user": self.user,
            "relation": self.relation,
            "object": self.object,
        })
    }
}

/// Optional evaluation parameters shared by check/expand/list endpoints.
///
/// Everything set here is passed through to OpenFGA verbatim.
#[derive(Debug, Clone, Default)]
pub struct RequestOptions {
    /// Evaluation context for conditions.
    pub context: Option<Value>,
    /// Contextual tuples used only for this evaluation.
    pub contextual_tuples: Vec<TupleKey>,
    /// Consistency preference (e.g. `minimize_latency`, `higher_consistency`).
    pub consistency: Option<String>,
}

impl RequestOptions {
    fn is_default(&self) -> bool {
        self.context.is_none() && self.contextual_tuples.is_empty() && self.consistency.is_none()
    }

    fn apply(&self, payload: &mut Value) {
        if self.is_default() {
            return;
        }
        if let Some(context) = &self.context {
            payload["context"] = context.clone();
        }
        if !self.contextual_tuples.is_empty() {
            payload["contextual_tuples"] = serde_json::json!({
                "tuple_keys": self.contextual_tuples.iter().map(TupleKey::to_write_json).collect::<Vec<_>>(),
            });
        }
        if let Some(consistency) = &self.consistency {
            payload["consistency"] = Value::String(consistency.clone());
        }
    }
}

/// Build a flat single-type authorization model for `namespace`.
///
/// Every relation is directly assignable by typed users. Used by gateway
/// flows (e.g. SCIM groups) that do not author rich models.
pub fn flat_model(namespace: &str, relations: &[String]) -> Value {
    serde_json::json!({
        "schema_version": "1.1",
        "type_definitions": build_namespace_model(namespace, relations),
    })
}

/// Canonicalize a list-users response entry into `type:id`,
/// `type:id#relation`, or `type:*`. Unknown shapes fall back to raw JSON.
fn canonical_user(entry: &Value) -> String {
    fn str_field(value: &Value, key: &str) -> String {
        match value.get(key).and_then(|v| v.as_str()) {
            Some(s) => s.to_owned(),
            None => String::new(),
        }
    }

    if let Some(object) = entry.get("object") {
        let ty = str_field(object, "type");
        let id = str_field(object, "id");
        return format!("{ty}:{id}");
    }
    if let Some(userset) = entry.get("userset") {
        let ty = str_field(userset, "type");
        let id = str_field(userset, "id");
        let relation = str_field(userset, "relation");
        return format!("{ty}:{id}#{relation}");
    }
    if let Some(wildcard) = entry.get("wildcard") {
        let ty = str_field(wildcard, "type");
        return format!("{ty}:*");
    }
    entry.to_string()
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
    let message = match response.text().await {
        Ok(body) => body,
        Err(err) => {
            tracing::warn!(%err, "failed to read openfga error body; falling back to placeholder");
            "<unreadable body>".to_string()
        }
    };
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
            .route("/stores/{store_id}/read", post(read_tuples))
            .route("/stores/{store_id}/check", post(check))
            .route("/stores/{store_id}/expand", post(expand))
            .route("/stores/{store_id}/list-objects", post(list_objects))
            .route("/stores/{store_id}/list-users", post(list_users))
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

    async fn read_tuples(
        State(state): State<FakeState>,
        Path(store_id): Path<String>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let key = body.get("tuple_key").cloned().unwrap_or_default();
        let user = key.get("user").and_then(|v| v.as_str()).unwrap_or("");
        let relation = key.get("relation").and_then(|v| v.as_str()).unwrap_or("");
        let object = key.get("object").and_then(|v| v.as_str()).unwrap_or("");
        let tuples: Vec<Value> = state
            .tuples
            .lock()
            .unwrap()
            .iter()
            .filter(|t| {
                t.get("store_id").and_then(|v| v.as_str()) == Some(&store_id)
                    && (user.is_empty() || t.get("user").and_then(|v| v.as_str()) == Some(user))
                    && (relation.is_empty()
                        || t.get("relation").and_then(|v| v.as_str()) == Some(relation))
                    && (object.is_empty()
                        || t.get("object").and_then(|v| v.as_str()) == Some(object))
            })
            .map(|t| {
                json!({ "key": {
                    "user": t.get("user"),
                    "relation": t.get("relation"),
                    "object": t.get("object"),
                } })
            })
            .collect();
        Json(json!({ "tuples": tuples, "continuation_token": "" }))
    }

    async fn check(
        State(state): State<FakeState>,
        Path(store_id): Path<String>,
        Json(body): Json<Value>,
    ) -> Json<Value> {        let key = body.get("tuple_key").cloned().unwrap_or_default();
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

    async fn list_users(
        State(state): State<FakeState>,
        Path(store_id): Path<String>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let object = body
            .get("object")
            .and_then(|o| o.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let object_type = body
            .get("object")
            .and_then(|o| o.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let relation = body.get("relation").and_then(|v| v.as_str()).unwrap_or("");
        let want_object = format!("{object_type}:{object}");
        let users: Vec<Value> = state
            .tuples
            .lock()
            .unwrap()
            .iter()
            .filter(|t| {
                t.get("store_id").and_then(|v| v.as_str()) == Some(&store_id)
                    && t.get("relation").and_then(|v| v.as_str()) == Some(relation)
                    && t.get("object").and_then(|v| v.as_str()) == Some(&want_object)
            })
            .filter_map(|t| t.get("user").and_then(|v| v.as_str()).map(String::from))
            .map(|user| match user.split_once(':') {
                Some((ty, id)) => json!({ "object": { "type": ty, "id": id } }),
                None => json!({ "object": { "type": "user", "id": user } }),
            })
            .collect();
        Json(json!({ "users": users }))
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
    async fn find_store_by_name_matches_and_misses() {
        let (_handle, url) = start_server().await;
        let client = OpenFgaClient::new(&url).unwrap();

        assert!(client.find_store_by_name("tenant-1-entitlements").await.unwrap().is_none());

        let store_id = client.create_store("tenant-1-entitlements").await.unwrap();
        client.create_store("tenant-1-kanban").await.unwrap();

        let found = client
            .find_store_by_name("tenant-1-entitlements")
            .await
            .unwrap();
        assert_eq!(found.as_deref(), Some(store_id.as_str()));
        assert!(client.find_store_by_name("tenant-2-entitlements").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_tuples_filters_exact_key() {
        let (_handle, url) = start_server().await;
        let client = OpenFgaClient::new(&url).unwrap();
        let store_id = client.create_store("reads").await.unwrap();
        let model_id = client
            .write_authorization_model(&store_id, "document", &["reader".into()])
            .await
            .unwrap();

        let key = TupleKey {
            user: "user:alice".into(),
            relation: "reader".into(),
            object: "document:doc-1".into(),
            condition_name: None,
            condition_context: None,
        };
        let other = TupleKey {
            user: "user:bob".into(),
            ..key.clone()
        };

        // Nothing stored yet.
        assert!(client.read_tuples(&store_id, &key).await.unwrap().is_empty());

        client
            .write_tuples(&store_id, &model_id, &[key.clone(), other], &[])
            .await
            .unwrap();

        // An exact key yields exactly the matching tuple.
        let found = client.read_tuples(&store_id, &key).await.unwrap();
        assert_eq!(found, vec![key.clone()]);
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
                &RequestOptions::default(),
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
                &RequestOptions::default(),
            )
            .await
            .unwrap();
        assert!(allowed);

        let objects = client
            .list_objects(
                &store_id,
                &model_id,
                "document",
                "reader",
                "user:alice",
                &RequestOptions::default(),
            )
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
                &RequestOptions::default(),
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
            .expand(
                &store_id,
                &model_id,
                "document",
                "doc-1",
                "reader",
                &RequestOptions::default(),
            )
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

    #[tokio::test]
    async fn write_tuples_batch_round_trip() {
        let (_handle, url) = start_server().await;
        let client = OpenFgaClient::new(&url).unwrap();
        let store_id = client.create_store("batch").await.unwrap();
        let model_id = client
            .write_authorization_model(&store_id, "document", &["reader".into()])
            .await
            .unwrap();

        client
            .write_tuples(&store_id, &model_id, &[], &[])
            .await
            .unwrap();

        let writes = vec![
            TupleKey {
                user: "user:alice".into(),
                relation: "reader".into(),
                object: "document:doc-1".into(),
                condition_name: None,
                condition_context: None,
            },
            TupleKey {
                user: "user:bob".into(),
                relation: "reader".into(),
                object: "document:doc-1".into(),
                condition_name: Some("in_range".into()),
                condition_context: Some(json!({ "x": 1 })),
            },
        ];
        client
            .write_tuples(&store_id, &model_id, &writes, &[])
            .await
            .unwrap();

        let users = client
            .list_users(
                &store_id,
                &model_id,
                "document",
                "doc-1",
                "reader",
                &["user".into()],
                &RequestOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(users, vec!["user:alice", "user:bob"]);

        client
            .write_tuples(&store_id, &model_id, &[], &writes[..1])
            .await
            .unwrap();
        let users = client
            .list_users(
                &store_id,
                &model_id,
                "document",
                "doc-1",
                "reader",
                &[],
                &RequestOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(users, vec!["user:bob"]);
    }

    #[tokio::test]
    async fn check_with_request_options_succeeds() {
        let (_handle, url) = start_server().await;
        let client = OpenFgaClient::new(&url).unwrap();
        let store_id = client.create_store("opts").await.unwrap();
        let model_id = client
            .write_authorization_model(&store_id, "document", &["reader".into()])
            .await
            .unwrap();

        let opts = RequestOptions {
            context: Some(json!({ "ip": "10.0.0.1" })),
            contextual_tuples: vec![TupleKey {
                user: "user:carol".into(),
                relation: "reader".into(),
                object: "document:doc-9".into(),
                condition_name: None,
                condition_context: None,
            }],
            consistency: Some("higher_consistency".into()),
        };
        // The fake server ignores the extra fields; this exercises payload
        // construction and the success path with options applied.
        let allowed = client
            .check(
                &store_id,
                &model_id,
                "document",
                "doc-9",
                "reader",
                "user:carol",
                &opts,
            )
            .await
            .unwrap();
        assert!(!allowed);
    }

    #[test]
    fn flat_model_builds_single_type_model() {
        let model = flat_model("document", &["reader".into(), "writer".into()]);
        assert_eq!(model["schema_version"], "1.1");
        let defs = model["type_definitions"].as_array().unwrap();
        assert_eq!(defs.len(), 2);
        assert_eq!(defs[0]["type"], "user");
        assert_eq!(defs[1]["type"], "document");
        assert!(defs[1]["relations"]["reader"].is_object());
        assert!(defs[1]["relations"]["writer"].is_object());
    }

    #[test]
    fn canonical_user_formats_all_shapes() {
        let object = json!({ "object": { "type": "user", "id": "anne" } });
        assert_eq!(canonical_user(&object), "user:anne");

        let userset = json!({ "userset": { "type": "team", "id": "eng", "relation": "member" } });
        assert_eq!(canonical_user(&userset), "team:eng#member");

        let wildcard = json!({ "wildcard": { "type": "user" } });
        assert_eq!(canonical_user(&wildcard), "user:*");

        let unknown = json!({ "something": true });
        assert_eq!(canonical_user(&unknown), r#"{"something":true}"#);
    }

    #[test]
    fn tuple_key_json_shapes() {
        let key = TupleKey {
            user: "user:a".into(),
            relation: "reader".into(),
            object: "document:1".into(),
            condition_name: Some("cond".into()),
            condition_context: Some(json!({ "k": "v" })),
        };
        let write = key.to_write_json();
        assert_eq!(write["condition"]["name"], "cond");
        assert_eq!(write["condition"]["context"]["k"], "v");
        let delete = key.to_delete_json();
        assert!(delete.get("condition").is_none());

        let plain = TupleKey {
            condition_name: None,
            condition_context: None,
            ..key.clone()
        };
        assert!(plain.to_write_json().get("condition").is_none());
    }

    #[test]
    fn request_options_apply_skips_defaults() {
        let opts = RequestOptions::default();
        assert!(opts.is_default());
        let mut payload = json!({ "a": 1 });
        opts.apply(&mut payload);
        assert_eq!(payload, json!({ "a": 1 }));

        let opts = RequestOptions {
            context: None,
            contextual_tuples: Vec::new(),
            consistency: Some("minimize_latency".into()),
        };
        assert!(!opts.is_default());
        let mut payload = json!({});
        opts.apply(&mut payload);
        assert_eq!(payload["consistency"], "minimize_latency");
        assert!(payload.get("context").is_none());
        assert!(payload.get("contextual_tuples").is_none());
    }
}
