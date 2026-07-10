//! Map Ory Kratos self-service JSON into gateway protobuf messages.
//!
//! This is the only module that knows Ory Kratos field names and shapes for
//! browser self-service flows. If the backend is swapped, replace this mapper.

use buffa_types::google::protobuf::Struct as ProtoStruct;
use serde_json::Value;

use crate::proto::iam::v1::{
    BrowserIdentity, BrowserSession, FlowError, LogoutFlow, OAuth2Client, OAuth2LoginRequest,
    RecoveryAddress, SelfServiceFlow, UiContainer, UiMessage, UiNode, UiNodeAnchorAttributes,
    UiNodeImageAttributes, UiNodeInputAttributes, UiNodeMeta, UiNodeScriptAttributes,
    UiNodeTextAttributes, UiText, VerifiableAddress,
};

use super::proto_util::{
    json_array_to_strings, json_bool, json_i64, json_str, json_to_struct, json_value_to_string,
    parse_timestamp,
};

pub fn ory_session_to_proto(value: &Value) -> BrowserSession {
    let identity = value.get("identity").cloned().unwrap_or_default();
    BrowserSession {
        id: json_str(value, "id"),
        identity_id: json_str(&identity, "id"),
        tenant_id: String::new(),
        active: json_bool(value, "active"),
        expires_at: parse_timestamp_opt(value.get("expires_at")),
        authenticated_at: parse_timestamp_opt(value.get("authenticated_at")),
        issued_at: parse_timestamp_opt(value.get("issued_at")),
        authenticator_assurance_level: json_str(value, "authenticator_assurance_level"),
        identity_traits: value
            .get("identity")
            .and_then(|identity| identity.get("traits"))
            .cloned()
            .and_then(json_to_struct)
            .map(Into::into)
            .unwrap_or_default(),
        identity: value
            .get("identity")
            .map(ory_identity_to_proto)
            .map(Into::into)
            .unwrap_or_default(),
        ..Default::default()
    }
}

pub fn ory_identity_to_proto(value: &Value) -> BrowserIdentity {
    BrowserIdentity {
        id: json_str(value, "id"),
        traits: value
            .get("traits")
            .cloned()
            .and_then(json_to_struct)
            .map(Into::into)
            .unwrap_or_default(),
        verifiable_addresses: value
            .get("verifiable_addresses")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().map(ory_verifiable_address_to_proto).collect())
            .unwrap_or_default(),
        recovery_addresses: value
            .get("recovery_addresses")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().map(ory_recovery_address_to_proto).collect())
            .unwrap_or_default(),
        created_at: parse_timestamp_opt(value.get("created_at")),
        updated_at: parse_timestamp_opt(value.get("updated_at")),
        schema_id: json_str(value, "schema_id"),
        ..Default::default()
    }
}

pub fn ory_verifiable_address_to_proto(value: &Value) -> VerifiableAddress {
    VerifiableAddress {
        id: json_str(value, "id"),
        value: json_str(value, "value"),
        verified: json_bool(value, "verified"),
        via: json_str(value, "via"),
        status: json_str(value, "status"),
        verified_at: parse_timestamp_opt(value.get("verified_at")),
        created_at: parse_timestamp_opt(value.get("created_at")),
        updated_at: parse_timestamp_opt(value.get("updated_at")),
        ..Default::default()
    }
}

pub fn ory_recovery_address_to_proto(value: &Value) -> RecoveryAddress {
    RecoveryAddress {
        id: json_str(value, "id"),
        value: json_str(value, "value"),
        via: json_str(value, "via"),
        created_at: parse_timestamp_opt(value.get("created_at")),
        updated_at: parse_timestamp_opt(value.get("updated_at")),
        ..Default::default()
    }
}

pub fn ory_flow_to_proto(value: &Value) -> SelfServiceFlow {
    SelfServiceFlow {
        id: json_str(value, "id"),
        r#type: json_str(value, "type"),
        state: json_str(value, "state"),
        expires_at: parse_timestamp_opt(value.get("expires_at")),
        issued_at: parse_timestamp_opt(value.get("issued_at")),
        return_to: json_str(value, "return_to"),
        request_url: json_str(value, "request_url"),
        active_method: json_str(value, "active"),
        identity_schema_id: json_str(value, "identity_schema_id"),
        oauth2_login_request: value
            .get("oauth2_login_request")
            .map(ory_oauth2_login_request_to_proto)
            .map(Into::into)
            .unwrap_or_default(),
        ui: value
            .get("ui")
            .map(ory_ui_container_to_proto)
            .map(Into::into)
            .unwrap_or_default(),
        refresh: json_bool(value, "refresh"),
        requested_aal: json_str(value, "requested_aal"),
        ..Default::default()
    }
}

pub fn ory_ui_container_to_proto(value: &Value) -> UiContainer {
    UiContainer {
        action: json_str(value, "action"),
        method: json_str(value, "method"),
        nodes: value
            .get("nodes")
            .and_then(|n| n.as_array())
            .map(|arr| arr.iter().map(ory_ui_node_to_proto).collect())
            .unwrap_or_default(),
        messages: value
            .get("messages")
            .and_then(|m| m.as_array())
            .map(|arr| arr.iter().map(ory_ui_message_to_proto).collect())
            .unwrap_or_default(),
        ..Default::default()
    }
}

pub fn ory_ui_node_to_proto(value: &Value) -> UiNode {
    let node_type = value
        .get("attributes")
        .and_then(|a| a.get("node_type"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let attributes = match node_type {
        "input" => value
            .get("attributes")
            .map(ory_ui_node_input_attributes_to_proto)
            .map(Into::into),
        "text" => value
            .get("attributes")
            .map(ory_ui_node_text_attributes_to_proto)
            .map(Into::into),
        "anchor" => value
            .get("attributes")
            .map(ory_ui_node_anchor_attributes_to_proto)
            .map(Into::into),
        "img" | "image" => value
            .get("attributes")
            .map(ory_ui_node_image_attributes_to_proto)
            .map(Into::into),
        "script" => value
            .get("attributes")
            .map(ory_ui_node_script_attributes_to_proto)
            .map(Into::into),
        _ => None,
    };

    UiNode {
        r#type: json_str(value, "type"),
        group: json_str(value, "group"),
        messages: value
            .get("messages")
            .and_then(|m| m.as_array())
            .map(|arr| arr.iter().map(ory_ui_message_to_proto).collect())
            .unwrap_or_default(),
        meta: value
            .get("meta")
            .map(ory_ui_node_meta_to_proto)
            .map(Into::into)
            .unwrap_or_default(),
        attributes,
        ..Default::default()
    }
}

pub fn ory_ui_node_meta_to_proto(value: &Value) -> UiNodeMeta {
    let label = value.get("label").cloned().unwrap_or_default();
    UiNodeMeta {
        label: label
            .as_object()
            .map(|_| ory_ui_text_to_proto(&label))
            .map(Into::into)
            .unwrap_or_default(),
        label_id: json_str(&label, "id"),
        label_text: json_str(&label, "text"),
        brand: json_str(value, "brand"),
        name: json_str(value, "name"),
        title: json_str(value, "title"),
        ..Default::default()
    }
}

pub fn ory_ui_text_to_proto(value: &Value) -> UiText {
    UiText {
        id: json_str(value, "id"),
        text: json_str(value, "text"),
        r#type: json_str(value, "type"),
        context: value
            .get("context")
            .cloned()
            .and_then(json_to_struct)
            .map(Into::into)
            .unwrap_or_default(),
        ..Default::default()
    }
}

/// Coerce an Ory UI input node's `value` into the single string an HTML form
/// control submits.
///
/// Kratos input node values are scalars in the normal case, but a refresh
/// (re-authentication) flow prefills the `identifier` node from the identity's
/// credential identifier. If that identifier was ever stored as a JSON array
/// (e.g. `["alice@example.com", "alice@example.com"]`), the generic
/// `json_value_to_string` would render it as the literal text
/// `["alice@example.com","alice@example.com"]`, which the browser then submits
/// verbatim. No identity matches that string, so the password check fails and
/// the login silently loops.
///
/// The array can reach us in two shapes:
///   * as a real JSON array (`value.as_array()`), or
///   * as a string that is itself the JSON encoding of such an array
///     (`value.as_str() == Some("[\"a\",\"a\"]")`), which is how Kratos
///     delivers the node value when the stored identifier is a stringified list.
///
/// Both must collapse to one string, and critically they must collapse on every
/// render: a failed submit re-renders the form with the same value, so if we
/// ever emit the array the browser multiplies the field and the next attempt
/// carries one more copy — the array grows by one element per failed attempt.
/// Collapsing to a scalar on every render breaks that cycle.
///
/// A genuinely multi-valued array (more than one distinct string) is left in
/// its JSON form so we never silently drop a value the caller may need.
fn input_value_to_string(value: &Value) -> String {
    if let Some(collapsed) = collapse_identical_string_array(value) {
        return collapsed;
    }
    json_value_to_string(value)
}

/// Collapse an array of strings that all reduce to one value down to that value.
/// Also handles a node value that is itself a string encoding of such an array.
/// Returns `None` for non-collapsible values so genuinely multi-valued arrays
/// are never silently merged.
fn collapse_identical_string_array(value: &Value) -> Option<String> {
    if let Some(arr) = value.as_array() {
        return collapse_str_array(arr);
    }
    if let Some(s) = value.as_str()
        && s.starts_with('[')
        && let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(s)
    {
        return collapse_str_array(&arr);
    }
    None
}

fn collapse_str_array(arr: &[Value]) -> Option<String> {
    let mut distinct: Vec<&str> = Vec::new();
    for item in arr {
        let s = item.as_str()?;
        if !distinct.contains(&s) {
            distinct.push(s);
        }
    }
    (distinct.len() == 1).then(|| distinct[0].to_string())
}

pub fn ory_ui_node_input_attributes_to_proto(value: &Value) -> UiNodeInputAttributes {
    UiNodeInputAttributes {
        name: json_str(value, "name"),
        r#type: json_str(value, "type"),
        value: input_value_to_string(value.get("value").unwrap_or(&Value::Null)),
        required: json_bool(value, "required"),
        disabled: json_bool(value, "disabled"),
        autocomplete: json_str(value, "autocomplete"),
        node_type: json_str(value, "node_type"),
        label: value
            .get("label")
            .map(ory_ui_text_to_proto)
            .map(Into::into)
            .unwrap_or_default(),
        pattern: json_str(value, "pattern"),
        maxlength: json_i64(value, "maxlength"),
        minlength: json_i64(value, "minlength"),
        placeholder: json_str(value, "placeholder"),
        onclick: json_str(value, "onclick"),
        src: json_str(value, "src"),
        nonce: json_str(value, "nonce"),
        crossorigin: json_str(value, "crossorigin"),
        integrity: json_str(value, "integrity"),
        r#async: json_bool(value, "async"),
        referrerpolicy: json_str(value, "referrerpolicy"),
        multiple: json_bool(value, "multiple"),
        step: json_value_to_string(value.get("step").unwrap_or(&Value::Null)),
        ..Default::default()
    }
}

pub fn ory_ui_node_text_attributes_to_proto(value: &Value) -> UiNodeTextAttributes {
    let text = value.get("text").cloned().unwrap_or_default();
    UiNodeTextAttributes {
        node_type: json_str(value, "node_type"),
        text: if text.is_object() {
            Some(ory_ui_text_to_proto(&text)).into()
        } else {
            Some(UiText {
                text: text.as_str().unwrap_or("").to_string(),
                ..Default::default()
            })
            .into()
        },
        ..Default::default()
    }
}

pub fn ory_ui_node_anchor_attributes_to_proto(value: &Value) -> UiNodeAnchorAttributes {
    UiNodeAnchorAttributes {
        href: json_str(value, "href"),
        title: json_str(value, "title"),
        id: json_str(value, "id"),
        node_type: json_str(value, "node_type"),
        ..Default::default()
    }
}

pub fn ory_ui_node_image_attributes_to_proto(value: &Value) -> UiNodeImageAttributes {
    UiNodeImageAttributes {
        src: json_str(value, "src"),
        width: json_i64(value, "width"),
        height: json_i64(value, "height"),
        id: json_str(value, "id"),
        node_type: json_str(value, "node_type"),
        ..Default::default()
    }
}

pub fn ory_ui_node_script_attributes_to_proto(value: &Value) -> UiNodeScriptAttributes {
    UiNodeScriptAttributes {
        src: json_str(value, "src"),
        r#async: json_bool(value, "async"),
        referrerpolicy: json_str(value, "referrerpolicy"),
        crossorigin: json_str(value, "crossorigin"),
        integrity: json_str(value, "integrity"),
        r#type: json_str(value, "type"),
        id: json_str(value, "id"),
        nonce: json_str(value, "nonce"),
        node_type: json_str(value, "node_type"),
        ..Default::default()
    }
}

pub fn ory_ui_message_to_proto(value: &Value) -> UiMessage {
    UiMessage {
        id: json_str(value, "id"),
        text: json_str(value, "text"),
        r#type: json_str(value, "type"),
        context: value
            .get("context")
            .cloned()
            .and_then(json_to_struct)
            .map(Into::into)
            .unwrap_or_default(),
        ..Default::default()
    }
}

pub fn ory_oauth2_login_request_to_proto(value: &Value) -> OAuth2LoginRequest {
    let client = value.get("client").cloned().unwrap_or_default();
    OAuth2LoginRequest {
        challenge: json_str(value, "challenge"),
        client_id: json_str(&client, "client_id"),
        client_name: json_str(&client, "client_name"),
        requested_scope: json_array_to_strings(
            value.get("requested_scope").unwrap_or(&Value::Null),
        ),
        requested_access_token_audience: json_array_to_strings(
            value
                .get("requested_access_token_audience")
                .unwrap_or(&Value::Null),
        ),
        subject: json_str(value, "subject"),
        skip: json_bool(value, "skip"),
        client: client
            .as_object()
            .map(|_| OAuth2Client::from(&client))
            .map(Into::into)
            .unwrap_or_default(),
        ..Default::default()
    }
}

pub fn ory_logout_flow_to_proto(value: &Value) -> LogoutFlow {
    LogoutFlow {
        id: json_str(value, "id"),
        logout_url: json_str(value, "logout_url"),
        logout_token: json_str(value, "logout_token"),
        ..Default::default()
    }
}

pub fn ory_flow_error_to_proto(value: &Value) -> FlowError {
    FlowError {
        id: json_str(value, "id"),
        error: value
            .get("error")
            .map(json_value_to_string)
            .unwrap_or_default(),
        created_at: parse_timestamp_opt(value.get("created_at")),
        expires_at: parse_timestamp_opt(value.get("expires_at")),
        ..Default::default()
    }
}

pub fn ory_webauthn_js_to_proto(content: &str) -> crate::proto::iam::v1::WebAuthnJsResponse {
    crate::proto::iam::v1::WebAuthnJsResponse {
        content: content.to_string(),
        ..Default::default()
    }
}

/// Convert a gateway protobuf Struct into a serde JSON Value for submission.
pub fn proto_struct_to_json(value: Option<&ProtoStruct>) -> Value {
    value
        .map(|s| serde_json::to_value(s).unwrap_or_default())
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()))
}

fn parse_timestamp_opt<T>(value: Option<&Value>) -> T
where
    T: From<buffa_types::google::protobuf::Timestamp> + Default,
{
    value
        .and_then(|v| v.as_str())
        .and_then(parse_timestamp)
        .map(Into::into)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn ory_session_to_proto_maps_fields() {
        let value = json!({
            "id": "session-1",
            "active": true,
            "expires_at": "2026-01-01T00:00:00Z",
            "authenticated_at": "2025-01-01T00:00:00Z",
            "issued_at": "2025-01-01T00:00:00Z",
            "authenticator_assurance_level": "aal1",
            "identity": {
                "id": "identity-1",
                "schema_id": "default",
                "traits": { "email": "a@example.com" },
                "verifiable_addresses": [
                    {
                        "id": "va-1",
                        "value": "a@example.com",
                        "verified": true,
                        "via": "email",
                        "status": "completed"
                    }
                ],
                "recovery_addresses": [
                    { "id": "ra-1", "value": "a@example.com", "via": "email" }
                ],
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2025-01-01T00:00:00Z"
            }
        });

        let proto = ory_session_to_proto(&value);
        assert_eq!(proto.id, "session-1");
        assert_eq!(proto.identity_id, "identity-1");
        assert!(proto.active);
        assert_eq!(proto.authenticator_assurance_level, "aal1");
        assert!(proto.expires_at.is_set());
        assert!(proto.identity_traits.is_set());
        assert!(proto.identity.is_set());
        let identity = proto.identity.as_option().unwrap();
        assert_eq!(identity.id, "identity-1");
        assert_eq!(identity.schema_id, "default");
        assert_eq!(identity.verifiable_addresses.len(), 1);
        assert!(identity.verifiable_addresses[0].verified);
        assert_eq!(identity.recovery_addresses.len(), 1);
        assert!(identity.updated_at.is_set());
    }

    #[test]
    fn ory_identity_to_proto_maps_addresses_and_metadata() {
        let value = json!({
            "id": "identity-1",
            "schema_id": "default",
            "traits": { "email": "a@example.com" },
            "verifiable_addresses": [
                {
                    "id": "va-1",
                    "value": "a@example.com",
                    "verified": false,
                    "via": "email",
                    "status": "sent"
                }
            ],
            "recovery_addresses": []
        });

        let proto = ory_identity_to_proto(&value);
        assert_eq!(proto.id, "identity-1");
        assert!(proto.traits.is_set());
        assert_eq!(proto.verifiable_addresses.len(), 1);
        assert_eq!(proto.verifiable_addresses[0].status, "sent");
        assert!(proto.recovery_addresses.is_empty());
    }

    #[test]
    fn ory_flow_to_proto_maps_fields() {
        let value = json!({
            "id": "flow-1",
            "type": "login",
            "state": "choose_method",
            "expires_at": "2026-01-01T00:00:00Z",
            "issued_at": "2025-01-01T00:00:00Z",
            "return_to": "http://return",
            "request_url": "http://request",
            "active": "password",
            "identity_schema_id": "default",
            "refresh": true,
            "requested_aal": "aal2",
            "oauth2_login_request": {
                "challenge": "challenge-1",
                "client": {
                    "client_id": "client-1",
                    "client_name": "App",
                    "skip_consent": true,
                    "skip_logout_consent": false
                },
                "requested_scope": ["openid"],
                "subject": "subject-1",
                "skip": true
            },
            "ui": {
                "action": "http://action",
                "method": "POST",
                "nodes": [
                    {
                        "type": "input",
                        "group": "password",
                        "attributes": {
                            "node_type": "input",
                            "name": "password",
                            "type": "password",
                            "value": "secret",
                            "required": true,
                            "disabled": false
                        }
                    }
                ],
                "messages": [{ "id": 1, "text": "hello", "type": "info" }]
            }
        });

        let proto = ory_flow_to_proto(&value);
        assert_eq!(proto.id, "flow-1");
        assert_eq!(proto.r#type, "login");
        assert_eq!(proto.state, "choose_method");
        assert_eq!(proto.return_to, "http://return");
        assert_eq!(proto.active_method, "password");
        assert!(proto.refresh);
        assert_eq!(proto.requested_aal, "aal2");
        assert!(proto.oauth2_login_request.is_set());
        let oauth2 = proto.oauth2_login_request.as_option().unwrap();
        assert!(oauth2.client.is_set());
        let client = oauth2.client.as_option().unwrap();
        assert!(client.skip_consent);
        assert!(!client.skip_logout_consent);
        assert!(proto.ui.is_set());
        let ui = proto.ui.as_option().unwrap();
        assert_eq!(ui.action, "http://action");
        assert_eq!(ui.nodes.len(), 1);
        assert_eq!(ui.messages.len(), 1);
    }

    #[test]
    fn ory_ui_container_to_proto_handles_unknown_node_type() {
        let value = json!({
            "action": "http://action",
            "method": "POST",
            "nodes": [
                {
                    "type": "input",
                    "group": "default",
                    "attributes": { "node_type": "unknown" }
                }
            ]
        });

        let proto = ory_ui_container_to_proto(&value);
        assert_eq!(proto.nodes.len(), 1);
        assert!(proto.nodes[0].attributes.is_none());
    }

    #[test]
    fn ory_logout_flow_to_proto_maps_fields() {
        let value = json!({
            "id": "logout-1",
            "logout_url": "http://logout",
            "logout_token": "token-1"
        });

        let proto = ory_logout_flow_to_proto(&value);
        assert_eq!(proto.id, "logout-1");
        assert_eq!(proto.logout_url, "http://logout");
        assert_eq!(proto.logout_token, "token-1");
    }

    #[test]
    fn ory_flow_error_to_proto_maps_fields() {
        let value = json!({
            "id": "error-1",
            "error": { "message": "oops" },
            "created_at": "2025-01-01T00:00:00Z",
            "expires_at": "2026-01-01T00:00:00Z"
        });

        let proto = ory_flow_error_to_proto(&value);
        assert_eq!(proto.id, "error-1");
        assert_eq!(proto.error, r#"{"message":"oops"}"#);
        assert!(proto.created_at.is_set());
        assert!(proto.expires_at.is_set());
    }

    #[test]
    fn ory_webauthn_js_to_proto_maps_content() {
        let proto = ory_webauthn_js_to_proto("console.log('webauthn');");
        assert_eq!(proto.content, "console.log('webauthn');");
    }

    #[test]
    fn proto_struct_to_json_defaults_to_empty_object() {
        let value = proto_struct_to_json(None);
        assert!(value.is_object());
        assert!(value.as_object().unwrap().is_empty());
    }

    #[test]
    fn ory_flow_to_proto_without_optional_fields() {
        let value = json!({ "id": "flow-1", "type": "login", "state": "choose_method" });
        let proto = ory_flow_to_proto(&value);
        assert_eq!(proto.id, "flow-1");
        assert!(!proto.oauth2_login_request.is_set());
        assert!(!proto.ui.is_set());
        assert!(!proto.refresh);
        assert_eq!(proto.requested_aal, "");
    }

    #[test]
    fn ory_ui_container_to_proto_handles_all_node_types() {
        let value = json!({
            "action": "http://action",
            "method": "POST",
            "nodes": [
                {
                    "type": "input",
                    "group": "password",
                    "attributes": {
                        "node_type": "input",
                        "name": "password",
                        "type": "password",
                        "value": "secret",
                        "required": true,
                        "disabled": false,
                        "autocomplete": "current-password",
                        "label": { "id": 101, "text": "Password", "type": "info" },
                        "pattern": ".{8,}",
                        "maxlength": 128,
                        "minlength": 8,
                        "placeholder": "Enter password"
                    }
                },
                {
                    "type": "text",
                    "group": "default",
                    "attributes": { "node_type": "text", "text": { "id": 1, "text": "hello" } }
                },
                {
                    "type": "a",
                    "group": "link",
                    "attributes": { "node_type": "anchor", "href": "http://x", "title": "x", "id": 2 }
                },
                {
                    "type": "img",
                    "group": "oidc",
                    "attributes": { "node_type": "img", "src": "http://i", "width": 100, "height": 200, "id": 3 }
                },
                {
                    "type": "script",
                    "group": "webauthn",
                    "attributes": {
                        "node_type": "script",
                        "src": "http://s",
                        "async": true,
                        "referrerpolicy": "origin",
                        "crossorigin": "anonymous",
                        "integrity": "sha256-x",
                        "type": "text/javascript",
                        "id": 4,
                        "nonce": "nonce-1"
                    }
                }
            ],
            "messages": [
                { "id": 1, "text": "hello", "type": "info", "context": { "foo": "bar", "count": 3 } }
            ]
        });

        let proto = ory_ui_container_to_proto(&value);
        assert_eq!(proto.nodes.len(), 5);
        assert!(proto.nodes[0].attributes.is_some());
        assert!(proto.nodes[2].attributes.is_some());
        assert!(proto.nodes[4].attributes.is_some());
        assert_eq!(proto.messages.len(), 1);

        let input = proto.nodes[0].attributes.as_ref().unwrap();
        match input {
            crate::proto::iam::v1::ui_node::Attributes::Input(attrs) => {
                assert!(attrs.label.is_set());
                assert_eq!(attrs.pattern, ".{8,}");
                assert_eq!(attrs.maxlength, 128);
                assert_eq!(attrs.minlength, 8);
                assert_eq!(attrs.placeholder, "Enter password");
            }
            _ => panic!("expected input attributes"),
        }

        let text = proto.nodes[1].attributes.as_ref().unwrap();
        match text {
            crate::proto::iam::v1::ui_node::Attributes::Text(attrs) => {
                assert!(attrs.text.is_set());
            }
            _ => panic!("expected text attributes"),
        }

        let script = proto.nodes[4].attributes.as_ref().unwrap();
        match script {
            crate::proto::iam::v1::ui_node::Attributes::Script(attrs) => {
                assert!(attrs.r#async);
            }
            _ => panic!("expected script attributes"),
        }

        assert!(proto.messages[0].context.is_set());
        let ctx = proto.messages[0].context.as_option().unwrap();
        assert_eq!(ctx.fields.get("foo").unwrap().as_str().unwrap(), "bar");
    }

    #[test]
    fn ory_session_to_proto_without_identity() {
        let value = json!({ "id": "session-1", "active": false });
        let proto = ory_session_to_proto(&value);
        assert_eq!(proto.id, "session-1");
        assert!(!proto.active);
        assert_eq!(proto.identity_id, "");
        assert!(!proto.identity.is_set());
    }

    #[test]
    fn ory_flow_error_to_proto_without_timestamps() {
        let value = json!({ "id": "error-1", "error": "oops" });
        let proto = ory_flow_error_to_proto(&value);
        assert_eq!(proto.id, "error-1");
        assert_eq!(proto.error, "oops");
        assert!(!proto.created_at.is_set());
    }

    #[test]
    fn ory_oauth2_login_request_to_proto_defaults() {
        let value = json!({ "challenge": "c", "subject": "s" });
        let proto = ory_oauth2_login_request_to_proto(&value);
        assert_eq!(proto.challenge, "c");
        assert_eq!(proto.subject, "s");
        assert!(proto.requested_scope.is_empty());
        assert!(!proto.skip);
        assert!(!proto.client.is_set());
    }

    #[test]
    fn ory_logout_flow_to_proto_defaults() {
        let proto = ory_logout_flow_to_proto(&json!({}));
        assert_eq!(proto.id, "");
        assert_eq!(proto.logout_url, "");
    }

    #[test]
    fn ory_ui_node_to_proto_maps_each_node_type() {
        let value = json!({
            "type": "input",
            "group": "password",
            "attributes": { "node_type": "input", "name": "password" },
            "messages": [{ "id": 1, "text": "msg", "type": "info" }],
            "meta": { "label": { "id": 1, "text": "label", "type": "info" } }
        });
        let proto = ory_ui_node_to_proto(&value);
        assert_eq!(proto.r#type, "input");
        assert_eq!(proto.group, "password");
        assert_eq!(proto.messages.len(), 1);
        assert!(proto.meta.is_set());
        let meta = proto.meta.as_option().unwrap();
        assert!(meta.label.is_set());
        assert!(proto.attributes.is_some());

        let value = json!({ "attributes": { "node_type": "unknown" } });
        let proto = ory_ui_node_to_proto(&value);
        assert!(proto.attributes.is_none());
    }

    #[test]
    fn ory_ui_node_input_attributes_to_proto_maps_fields() {
        let value = json!({
            "name": "email",
            "type": "email",
            "value": "a@example.com",
            "required": true,
            "disabled": false,
            "autocomplete": "email",
            "node_type": "input",
            "label": { "id": 1, "text": "Email", "type": "info" },
            "pattern": ".*@.*",
            "maxlength": 256,
            "minlength": 3,
            "placeholder": "email@example.com"
        });
        let proto = ory_ui_node_input_attributes_to_proto(&value);
        assert_eq!(proto.name, "email");
        assert_eq!(proto.r#type, "email");
        assert_eq!(proto.value, "a@example.com");
        assert!(proto.required);
        assert!(!proto.disabled);
        assert_eq!(proto.autocomplete, "email");
        assert_eq!(proto.node_type, "input");
        assert!(proto.label.is_set());
        assert_eq!(proto.pattern, ".*@.*");
        assert_eq!(proto.maxlength, 256);
        assert_eq!(proto.minlength, 3);
        assert_eq!(proto.placeholder, "email@example.com");
    }

    // Regression: a refresh flow whose identifier Kratos prefilled as a JSON
    // array of the same email must collapse to a single scalar. Otherwise the
    // browser submits the literal `[...]` string and the password check never
    // matches an identity.
    #[test]
    fn ory_ui_node_input_attributes_to_proto_collapses_duplicated_identifier_array() {
        let value = json!({
            "name": "identifier",
            "type": "text",
            "value": ["sienna@sunbeam.pt", "sienna@sunbeam.pt"],
            "node_type": "input"
        });
        let proto = ory_ui_node_input_attributes_to_proto(&value);
        assert_eq!(proto.value, "sienna@sunbeam.pt");
    }

    #[test]
    fn ory_ui_node_input_attributes_to_proto_collapses_single_element_array() {
        let value = json!({
            "name": "identifier",
            "type": "text",
            "value": ["alice@example.com"],
            "node_type": "input"
        });
        let proto = ory_ui_node_input_attributes_to_proto(&value);
        assert_eq!(proto.value, "alice@example.com");
    }

    #[test]
    fn ory_ui_node_input_attributes_to_proto_keeps_distinct_array_as_json() {
        let value = json!({
            "name": "identifier",
            "type": "text",
            "value": ["alice@example.com", "bob@example.com"],
            "node_type": "input"
        });
        let proto = ory_ui_node_input_attributes_to_proto(&value);
        assert_eq!(proto.value, r#"["alice@example.com","bob@example.com"]"#);
    }

    #[test]
    fn ory_ui_node_input_attributes_to_proto_keeps_scalar_value() {
        let value = json!({
            "name": "identifier",
            "type": "text",
            "value": "alice@example.com",
            "node_type": "input"
        });
        let proto = ory_ui_node_input_attributes_to_proto(&value);
        assert_eq!(proto.value, "alice@example.com");
    }

    // Kratos delivers the refresh-flow identifier node value as a *string* that
    // is itself the JSON encoding of the duplicated array — the array-only
    // collapse (value.as_array()) misses it and the form renders the literal
    // `[...]` text. This is the exact shape reported in production.
    #[test]
    fn ory_ui_node_input_attributes_to_proto_collapses_string_encoded_identifier_array() {
        let value = json!({
            "name": "identifier",
            "type": "text",
            "value": "[\"sienna@sunbeam.pt\",\"sienna@sunbeam.pt\"]",
            "node_type": "input"
        });
        let proto = ory_ui_node_input_attributes_to_proto(&value);
        assert_eq!(proto.value, "sienna@sunbeam.pt");
    }

    // A failed submit re-renders the form with the same value. If we ever emit
    // the array, the browser multiplies the field and the next attempt carries
    // one more copy — the array grows by one element per attempt. Collapsing
    // the string-encoded array to a scalar on every render breaks that cycle:
    // feeding the collapsed result back in must stay a scalar, never re-array.
    #[test]
    fn ory_ui_node_input_attributes_to_proto_string_encoded_array_does_not_grow_on_rerender() {
        let value = json!({
            "name": "identifier",
            "type": "text",
            "value": "[\"sienna@sunbeam.pt\",\"sienna@sunbeam.pt\"]",
            "node_type": "input"
        });
        let first = ory_ui_node_input_attributes_to_proto(&value).value;
        assert_eq!(first, "sienna@sunbeam.pt");

        // Simulate the next render: the collapsed scalar is what the browser
        // submits back, so it arrives as a plain string — never an array.
        let rerendered = json!({
            "name": "identifier",
            "type": "text",
            "value": first,
            "node_type": "input"
        });
        let second = ory_ui_node_input_attributes_to_proto(&rerendered).value;
        assert_eq!(second, "sienna@sunbeam.pt");
        assert!(!second.starts_with('['));
    }

    // A string that looks like an array but holds distinct values is genuinely
    // multi-valued and must not be silently merged.
    #[test]
    fn ory_ui_node_input_attributes_to_proto_keeps_distinct_string_encoded_array_as_json() {
        let value = json!({
            "name": "identifier",
            "type": "text",
            "value": "[\"alice@example.com\",\"bob@example.com\"]",
            "node_type": "input"
        });
        let proto = ory_ui_node_input_attributes_to_proto(&value);
        assert_eq!(proto.value, r#"["alice@example.com","bob@example.com"]"#);
    }

    #[test]
    fn ory_ui_node_text_attributes_to_proto_maps_object_and_string_text() {
        let value =
            json!({ "node_type": "text", "text": { "id": "1", "text": "hello", "type": "info" } });
        let proto = ory_ui_node_text_attributes_to_proto(&value);
        assert_eq!(proto.node_type, "text");
        assert!(proto.text.is_set());
        let text = proto.text.as_option().unwrap();
        assert_eq!(text.text, "hello");

        let value = json!({ "node_type": "text", "text": "plain" });
        let proto = ory_ui_node_text_attributes_to_proto(&value);
        let text = proto.text.as_option().unwrap();
        assert_eq!(text.text, "plain");
    }

    #[test]
    fn ory_ui_node_anchor_attributes_to_proto_maps_fields() {
        let value = json!({ "href": "http://x", "title": "x", "id": "2", "node_type": "anchor" });
        let proto = ory_ui_node_anchor_attributes_to_proto(&value);
        assert_eq!(proto.href, "http://x");
        assert_eq!(proto.title, "x");
        assert_eq!(proto.id, "2");
        assert_eq!(proto.node_type, "anchor");
    }

    #[test]
    fn ory_ui_node_image_attributes_to_proto_maps_fields() {
        let value = json!({ "src": "http://i", "width": 100, "height": 200, "id": "3", "node_type": "img" });
        let proto = ory_ui_node_image_attributes_to_proto(&value);
        assert_eq!(proto.src, "http://i");
        assert_eq!(proto.width, 100);
        assert_eq!(proto.height, 200);
        assert_eq!(proto.id, "3");
        assert_eq!(proto.node_type, "img");
    }

    #[test]
    fn ory_ui_node_script_attributes_to_proto_maps_fields() {
        let value = json!({
            "src": "http://s",
            "async": true,
            "referrerpolicy": "origin",
            "crossorigin": "anonymous",
            "integrity": "sha256-x",
            "type": "text/javascript",
            "id": "4",
            "nonce": "nonce-1",
            "node_type": "script"
        });
        let proto = ory_ui_node_script_attributes_to_proto(&value);
        assert_eq!(proto.src, "http://s");
        assert!(proto.r#async);
        assert_eq!(proto.referrerpolicy, "origin");
        assert_eq!(proto.crossorigin, "anonymous");
        assert_eq!(proto.integrity, "sha256-x");
        assert_eq!(proto.r#type, "text/javascript");
        assert_eq!(proto.id, "4");
        assert_eq!(proto.nonce, "nonce-1");
        assert_eq!(proto.node_type, "script");
    }

    #[test]
    fn ory_ui_message_to_proto_maps_fields() {
        let value = json!({
            "id": "1",
            "text": "hello",
            "type": "info",
            "context": { "foo": "bar", "count": 3 }
        });
        let proto = ory_ui_message_to_proto(&value);
        assert_eq!(proto.id, "1");
        assert_eq!(proto.text, "hello");
        assert_eq!(proto.r#type, "info");
        assert!(proto.context.is_set());
        let ctx = proto.context.as_option().unwrap();
        assert!(ctx.fields.contains_key("foo"));
        assert!(ctx.fields.contains_key("count"));
    }

    #[test]
    fn ory_ui_text_to_proto_maps_context() {
        let value = json!({
            "id": 123,
            "text": "hello",
            "type": "info",
            "context": { "name": "world" }
        });
        let proto = ory_ui_text_to_proto(&value);
        assert_eq!(proto.text, "hello");
        assert_eq!(proto.r#type, "info");
        assert!(proto.context.is_set());
    }

    #[test]
    fn ory_oauth2_client_to_proto_maps_all_fields() {
        let value = json!({
            "client_id": "client-1",
            "client_name": "App",
            "client_uri": "http://app",
            "logo_uri": "http://logo",
            "redirect_uris": ["http://callback"],
            "skip_consent": true,
            "skip_logout_consent": true,
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid profile",
            "policy_uri": "http://policy",
            "tos_uri": "http://tos",
            "jwks_uri": "http://jwks",
            "metadata": { "custom": "value" }
        });
        let proto = OAuth2Client::from(&value);
        assert_eq!(proto.client_id, "client-1");
        assert_eq!(proto.client_name, "App");
        assert_eq!(proto.redirect_uris, vec!["http://callback"]);
        assert!(proto.skip_consent);
        assert!(proto.skip_logout_consent);
        assert!(proto.metadata.is_set());
    }

    #[test]
    fn ory_session_to_proto_handles_missing_optional_fields() {
        let value = json!({ "id": "session-1" });
        let proto = ory_session_to_proto(&value);
        assert_eq!(proto.id, "session-1");
        assert!(!proto.active);
        assert!(!proto.expires_at.is_set());
        assert!(!proto.authenticated_at.is_set());
        assert!(!proto.issued_at.is_set());
        assert!(!proto.identity_traits.is_set());
        assert!(!proto.identity.is_set());
    }

    #[test]
    fn ory_flow_to_proto_gap_fill_cases() {
        let value = json!({
            "id": "flow-2",
            "type": "registration",
            "state": "passed_challenge",
            "oauth2_login_request": {
                "challenge": "challenge-2",
                "client": { "client_id": "client-2", "client_name": "App Two" },
                "requested_scope": ["openid", "profile"],
                "requested_access_token_audience": ["aud-1", "aud-2"],
                "subject": "subject-2",
                "skip": false
            },
            "ui": {
                "action": "http://action",
                "method": "POST",
                "nodes": [
                    { "type": "text", "group": "default", "attributes": { "node_type": "text", "text": { "id": 1, "text": "hello" } } }
                ],
                "messages": []
            }
        });
        let proto = ory_flow_to_proto(&value);
        assert_eq!(proto.id, "flow-2");
        assert!(proto.oauth2_login_request.is_set());
        let oauth2 = proto.oauth2_login_request.as_option().unwrap();
        assert_eq!(oauth2.client_name, "App Two");
        assert_eq!(oauth2.requested_scope, vec!["openid", "profile"]);
        assert_eq!(
            oauth2.requested_access_token_audience,
            vec!["aud-1", "aud-2"]
        );
        assert!(!oauth2.skip);
        let ui = proto.ui.as_option().unwrap();
        assert_eq!(ui.nodes.len(), 1);
    }

    #[test]
    fn ory_oauth2_login_request_to_proto_maps_all_fields() {
        let value = json!({
            "challenge": "challenge-3",
            "client": {
                "client_id": "client-3",
                "client_name": "App Three",
                "skip_consent": true,
                "skip_logout_consent": false
            },
            "requested_scope": ["openid"],
            "requested_access_token_audience": ["aud-3"],
            "subject": "subject-3",
            "skip": true
        });
        let proto = ory_oauth2_login_request_to_proto(&value);
        assert_eq!(proto.challenge, "challenge-3");
        assert_eq!(proto.client_id, "client-3");
        assert_eq!(proto.client_name, "App Three");
        assert_eq!(proto.requested_scope, vec!["openid"]);
        assert_eq!(proto.requested_access_token_audience, vec!["aud-3"]);
        assert_eq!(proto.subject, "subject-3");
        assert!(proto.skip);
        assert!(proto.client.is_set());
        let client = proto.client.as_option().unwrap();
        assert!(client.skip_consent);
        assert!(!client.skip_logout_consent);
    }
}
