//! Map Ory Kratos self-service JSON into gateway protobuf messages.
//!
//! This is the only module that knows Ory Kratos field names and shapes for
//! browser self-service flows. If the backend is swapped, replace this mapper.

use buffa_types::google::protobuf::Struct as ProtoStruct;
use serde_json::Value;

use crate::proto::iam::v1::{
    BrowserSession, FlowError, LogoutFlow, OAuth2LoginRequest, SelfServiceFlow, UiContainer,
    UiMessage, UiMessageContext, UiNode, UiNodeAnchorAttributes, UiNodeImageAttributes,
    UiNodeInputAttributes, UiNodeMeta, UiNodeScriptAttributes, UiNodeTextAttributes,
};

use super::proto_util::{
    json_array_to_strings, json_bool, json_str, json_to_struct, json_value_to_string,
    parse_timestamp,
};

pub fn ory_session_to_proto(value: &Value) -> BrowserSession {
    BrowserSession {
        id: json_str(value, "id"),
        identity_id: json_str(&value.get("identity").cloned().unwrap_or_default(), "id"),
        tenant_id: String::new(),
        active: json_bool(value, "active"),
        expires_at: value
            .get("expires_at")
            .and_then(|v| v.as_str())
            .and_then(parse_timestamp)
            .map(Into::into)
            .unwrap_or_default(),
        authenticated_at: value
            .get("authenticated_at")
            .and_then(|v| v.as_str())
            .and_then(parse_timestamp)
            .map(Into::into)
            .unwrap_or_default(),
        issued_at: value
            .get("issued_at")
            .and_then(|v| v.as_str())
            .and_then(parse_timestamp)
            .map(Into::into)
            .unwrap_or_default(),
        authenticator_assurance_level: json_str(value, "authenticator_assurance_level"),
        identity_traits: value
            .get("identity")
            .and_then(|identity| identity.get("traits"))
            .cloned()
            .and_then(json_to_struct)
            .map(Into::into)
            .unwrap_or_default(),
        ..Default::default()
    }
}

pub fn ory_flow_to_proto(value: &Value) -> SelfServiceFlow {
    SelfServiceFlow {
        id: json_str(value, "id"),
        r#type: json_str(value, "type"),
        state: json_str(value, "state"),
        expires_at: value
            .get("expires_at")
            .and_then(|v| v.as_str())
            .and_then(parse_timestamp)
            .map(Into::into)
            .unwrap_or_default(),
        issued_at: value
            .get("issued_at")
            .and_then(|v| v.as_str())
            .and_then(parse_timestamp)
            .map(Into::into)
            .unwrap_or_default(),
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
        label_id: json_str(&label, "id"),
        label_text: json_str(&label, "text"),
        ..Default::default()
    }
}

pub fn ory_ui_node_input_attributes_to_proto(value: &Value) -> UiNodeInputAttributes {
    UiNodeInputAttributes {
        name: json_str(value, "name"),
        r#type: json_str(value, "type"),
        value: json_value_to_string(value.get("value").unwrap_or(&Value::Null)),
        required: json_bool(value, "required"),
        disabled: json_bool(value, "disabled"),
        autocomplete: json_str(value, "autocomplete"),
        node_type: json_str(value, "node_type"),
        ..Default::default()
    }
}

pub fn ory_ui_node_text_attributes_to_proto(value: &Value) -> UiNodeTextAttributes {
    UiNodeTextAttributes {
        id: json_str(value, "id"),
        text: json_str(value, "text"),
        ..Default::default()
    }
}

pub fn ory_ui_node_anchor_attributes_to_proto(value: &Value) -> UiNodeAnchorAttributes {
    UiNodeAnchorAttributes {
        href: json_str(value, "href"),
        title: json_str(value, "title"),
        id: json_str(value, "id"),
        ..Default::default()
    }
}

pub fn ory_ui_node_image_attributes_to_proto(value: &Value) -> UiNodeImageAttributes {
    UiNodeImageAttributes {
        src: json_str(value, "src"),
        width: json_value_to_string(value.get("width").unwrap_or(&Value::Null)),
        height: json_value_to_string(value.get("height").unwrap_or(&Value::Null)),
        id: json_str(value, "id"),
        ..Default::default()
    }
}

pub fn ory_ui_node_script_attributes_to_proto(value: &Value) -> UiNodeScriptAttributes {
    UiNodeScriptAttributes {
        src: json_str(value, "src"),
        r#async: json_value_to_string(value.get("async").unwrap_or(&Value::Null)),
        referrerpolicy: json_str(value, "referrerpolicy"),
        crossorigin: json_str(value, "crossorigin"),
        integrity: json_str(value, "integrity"),
        r#type: json_str(value, "type"),
        id: json_str(value, "id"),
        nonce: json_str(value, "nonce"),
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
            .and_then(|c| c.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| UiMessageContext {
                        key: k.clone(),
                        value: json_value_to_string(v),
                        __buffa_unknown_fields: Default::default(),
                    })
                    .collect()
            })
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
        created_at: value
            .get("created_at")
            .and_then(|v| v.as_str())
            .and_then(parse_timestamp)
            .map(Into::into)
            .unwrap_or_default(),
        expires_at: value
            .get("expires_at")
            .and_then(|v| v.as_str())
            .and_then(parse_timestamp)
            .map(Into::into)
            .unwrap_or_default(),
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
                "traits": { "email": "a@example.com" }
            }
        });

        let proto = ory_session_to_proto(&value);
        assert_eq!(proto.id, "session-1");
        assert_eq!(proto.identity_id, "identity-1");
        assert!(proto.active);
        assert_eq!(proto.authenticator_assurance_level, "aal1");
        assert!(proto.expires_at.is_set());
        assert!(proto.identity_traits.is_set());
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
            "oauth2_login_request": {
                "challenge": "challenge-1",
                "client": { "client_id": "client-1", "client_name": "App" },
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
        assert!(proto.oauth2_login_request.is_set());
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
                        "autocomplete": "current-password"
                    }
                },
                {
                    "type": "text",
                    "group": "default",
                    "attributes": { "node_type": "text", "id": 1, "text": "hello" }
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
                { "id": 1, "text": "hello", "type": "info", "context": { "foo": "bar" } }
            ]
        });

        let proto = ory_ui_container_to_proto(&value);
        assert_eq!(proto.nodes.len(), 5);
        assert!(proto.nodes[0].attributes.is_some());
        assert!(proto.nodes[2].attributes.is_some());
        assert!(proto.nodes[4].attributes.is_some());
        assert_eq!(proto.messages.len(), 1);
        assert_eq!(proto.messages[0].context.len(), 1);
        assert_eq!(proto.messages[0].context[0].value, "bar");
    }

    #[test]
    fn ory_session_to_proto_without_identity() {
        let value = json!({ "id": "session-1", "active": false });
        let proto = ory_session_to_proto(&value);
        assert_eq!(proto.id, "session-1");
        assert!(!proto.active);
        assert_eq!(proto.identity_id, "");
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
    }

    #[test]
    fn ory_logout_flow_to_proto_defaults() {
        let proto = ory_logout_flow_to_proto(&json!({}));
        assert_eq!(proto.id, "");
        assert_eq!(proto.logout_url, "");
    }
}
