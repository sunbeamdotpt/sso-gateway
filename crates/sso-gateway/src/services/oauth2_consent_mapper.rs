//! Map Ory Hydra consent/logout JSON into gateway protobuf messages.
//!
//! This is the only module that knows Ory Hydra consent/logout request shapes.
//! If the backend is swapped, replace this mapper.

use serde_json::{Map, Value};

use crate::proto::iam::v1::{
    AcceptConsentRequest, AcceptLogoutRequest, ConsentRequest, ConsentResponse, LogoutRequest,
    LogoutResponse, RejectConsentRequest, RejectLogoutRequest,
};

use super::proto_util::{
    json_array_to_strings, json_bool, json_str, json_to_struct, json_value_to_string,
};

pub fn ory_consent_request_to_proto(value: &Value) -> ConsentRequest {
    let client = value.get("client").cloned().unwrap_or_default();
    ConsentRequest {
        challenge: json_str(value, "challenge"),
        client_id: json_str(&client, "client_id"),
        client_name: json_str(&client, "client_name"),
        subject: json_str(value, "subject"),
        skip: json_bool(value, "skip"),
        requested_scope: json_array_to_strings(
            value.get("requested_scope").unwrap_or(&Value::Null),
        ),
        requested_access_token_audience: json_array_to_strings(
            value
                .get("requested_access_token_audience")
                .unwrap_or(&Value::Null),
        ),
        oidc_context: value
            .get("oidc_context")
            .cloned()
            .and_then(json_to_struct)
            .map(Into::into)
            .unwrap_or_default(),
        ..Default::default()
    }
}

pub fn ory_consent_response_to_proto(value: &Value) -> ConsentResponse {
    ConsentResponse {
        redirect_to: json_str(value, "redirect_to"),
        ..Default::default()
    }
}

pub fn accept_consent_request_to_json(req: &AcceptConsentRequest) -> Value {
    let mut body = Map::new();
    body.insert(
        "grant_scope".to_string(),
        req.grant_scope.iter().cloned().map(Value::String).collect(),
    );
    body.insert(
        "grant_access_token_audience".to_string(),
        req.grant_access_token_audience
            .iter()
            .cloned()
            .map(Value::String)
            .collect(),
    );
    body.insert("remember".to_string(), Value::Bool(req.remember));
    if req.remember_for != 0 {
        body.insert(
            "remember_for".to_string(),
            Value::Number(req.remember_for.into()),
        );
    }
    if let Some(session) = req.session.as_option() {
        body.insert(
            "session".to_string(),
            serde_json::to_value(session).unwrap_or_default(),
        );
    }
    Value::Object(body)
}

pub fn reject_consent_request_to_json(req: &RejectConsentRequest) -> Value {
    let mut body = Map::new();
    if !req.error.is_empty() {
        body.insert("error".to_string(), Value::String(req.error.clone()));
    }
    if !req.error_description.is_empty() {
        body.insert(
            "error_description".to_string(),
            Value::String(req.error_description.clone()),
        );
    }
    if !req.error_hint.is_empty() {
        body.insert(
            "error_hint".to_string(),
            Value::String(req.error_hint.clone()),
        );
    }
    if req.status_code != 0 {
        body.insert(
            "status_code".to_string(),
            Value::Number(req.status_code.into()),
        );
    }
    Value::Object(body)
}

pub fn ory_logout_request_to_proto(value: &Value) -> LogoutRequest {
    let client = value.get("client").cloned().unwrap_or_default();
    let client_id = if client.is_object() {
        json_str(&client, "client_id")
    } else {
        json_value_to_string(&client)
    };
    LogoutRequest {
        challenge: json_str(value, "challenge"),
        subject: json_str(value, "subject"),
        client_id,
        request_url: json_str(value, "request_url"),
        post_logout_redirect_uri: json_str(value, "post_logout_redirect_uri"),
        ..Default::default()
    }
}

pub fn ory_logout_response_to_proto(value: &Value) -> LogoutResponse {
    LogoutResponse {
        redirect_to: json_str(value, "redirect_to"),
        ..Default::default()
    }
}

pub fn accept_logout_request_to_json(_req: &AcceptLogoutRequest) -> Value {
    Value::Object(Map::new())
}

pub fn reject_logout_request_to_json(req: &RejectLogoutRequest) -> Value {
    let mut body = Map::new();
    if !req.error.is_empty() {
        body.insert("error".to_string(), Value::String(req.error.clone()));
    }
    if !req.error_description.is_empty() {
        body.insert(
            "error_description".to_string(),
            Value::String(req.error_description.clone()),
        );
    }
    if !req.error_hint.is_empty() {
        body.insert(
            "error_hint".to_string(),
            Value::String(req.error_hint.clone()),
        );
    }
    if req.status_code != 0 {
        body.insert(
            "status_code".to_string(),
            Value::Number(req.status_code.into()),
        );
    }
    Value::Object(body)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn ory_consent_request_to_proto_maps_fields() {
        let value = json!({
            "challenge": "challenge-1",
            "client": { "client_id": "client-1", "client_name": "App" },
            "subject": "subject-1",
            "skip": true,
            "requested_scope": ["openid", "profile"],
            "requested_access_token_audience": ["aud"],
            "oidc_context": { "acr_values": ["aal1"] }
        });

        let proto = ory_consent_request_to_proto(&value);
        assert_eq!(proto.challenge, "challenge-1");
        assert_eq!(proto.client_id, "client-1");
        assert_eq!(proto.client_name, "App");
        assert_eq!(proto.subject, "subject-1");
        assert!(proto.skip);
        assert_eq!(proto.requested_scope, vec!["openid", "profile"]);
        assert_eq!(proto.requested_access_token_audience, vec!["aud"]);
        assert!(proto.oidc_context.is_set());
    }

    #[test]
    fn ory_consent_response_to_proto_maps_redirect_to() {
        let value = json!({ "redirect_to": "http://redirect" });
        let proto = ory_consent_response_to_proto(&value);
        assert_eq!(proto.redirect_to, "http://redirect");
    }

    #[test]
    fn accept_consent_request_to_json_maps_fields() {
        let req = AcceptConsentRequest {
            challenge: "challenge-1".to_string(),
            grant_scope: vec!["openid".to_string()],
            grant_access_token_audience: vec!["aud".to_string()],
            remember: true,
            remember_for: 3600,
            ..Default::default()
        };

        let value = accept_consent_request_to_json(&req);
        assert_eq!(value["grant_scope"], json![["openid"]]);
        assert_eq!(value["grant_access_token_audience"], json![["aud"]]);
        assert_eq!(value["remember"], true);
        assert_eq!(value["remember_for"], 3600);
    }

    #[test]
    fn reject_consent_request_to_json_omits_empty_fields() {
        let req = RejectConsentRequest {
            challenge: "challenge-1".to_string(),
            error: "access_denied".to_string(),
            ..Default::default()
        };

        let value = reject_consent_request_to_json(&req);
        assert_eq!(value["error"], "access_denied");
        assert!(value.get("error_description").is_none());
        assert!(value.get("status_code").is_none());
    }

    #[test]
    fn ory_logout_request_to_proto_maps_fields() {
        let value = json!({
            "challenge": "logout-challenge-1",
            "subject": "subject-1",
            "client": { "client_id": "client-1" },
            "request_url": "http://request",
            "post_logout_redirect_uri": "http://redirect"
        });

        let proto = ory_logout_request_to_proto(&value);
        assert_eq!(proto.challenge, "logout-challenge-1");
        assert_eq!(proto.subject, "subject-1");
        assert_eq!(proto.client_id, "client-1");
        assert_eq!(proto.request_url, "http://request");
        assert_eq!(proto.post_logout_redirect_uri, "http://redirect");
    }

    #[test]
    fn ory_logout_request_to_proto_falls_back_to_string_client() {
        let value = json!({
            "challenge": "logout-challenge-1",
            "client": "client-1",
            "subject": "subject-1"
        });

        let proto = ory_logout_request_to_proto(&value);
        assert_eq!(proto.client_id, "client-1");
    }

    #[test]
    fn ory_logout_response_to_proto_maps_redirect_to() {
        let value = json!({ "redirect_to": "http://redirect" });
        let proto = ory_logout_response_to_proto(&value);
        assert_eq!(proto.redirect_to, "http://redirect");
    }

    #[test]
    fn accept_logout_request_to_json_is_empty_object() {
        let req = AcceptLogoutRequest {
            challenge: "challenge-1".to_string(),
            ..Default::default()
        };
        let value = accept_logout_request_to_json(&req);
        assert!(value.is_object());
        assert!(value.as_object().unwrap().is_empty());
    }

    #[test]
    fn reject_logout_request_to_json_maps_fields() {
        let req = RejectLogoutRequest {
            challenge: "challenge-1".to_string(),
            error: "invalid_request".to_string(),
            error_description: "bad".to_string(),
            error_hint: "hint".to_string(),
            status_code: 400,
            ..Default::default()
        };

        let value = reject_logout_request_to_json(&req);
        assert_eq!(value["error"], "invalid_request");
        assert_eq!(value["error_description"], "bad");
        assert_eq!(value["error_hint"], "hint");
        assert_eq!(value["status_code"], 400);
    }
}
