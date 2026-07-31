//! Shared helpers for translating JSON into generated protobuf types.
//!
//! These utilities are backend-agnostic: they know protobuf shape but do not
//! know Ory field names. Ory-specific parsing belongs in the mapper modules.

use buffa_types::google::protobuf::{Struct as ProtoStruct, Timestamp};
use serde_json::Value;

/// Parse an RFC3339 timestamp into a protobuf Timestamp.
pub fn parse_timestamp(value: &str) -> Option<Timestamp> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| Timestamp {
            seconds: dt.timestamp(),
            nanos: dt.timestamp_subsec_nanos() as i32,
            ..Default::default()
        })
}

/// Convert a JSON object into a protobuf Struct.
pub fn json_to_struct(value: Value) -> Option<ProtoStruct> {
    if value.is_object() {
        serde_json::from_value::<ProtoStruct>(value).ok()
    } else {
        None
    }
}

/// Convert a JSON array into a Vec<String>, falling back to the JSON display
/// form for non-string items.
pub fn json_array_to_strings(value: &Value) -> Vec<String> {
    match value.as_array() {
        Some(arr) => arr.iter().map(json_value_to_string).collect::<Vec<_>>(),
        None => Vec::new(),
    }
}

/// Best-effort string extraction from a JSON value.
pub fn json_value_to_string(value: &Value) -> String {
    match value.as_str() {
        Some(s) => String::from(s),
        None => value.to_string(),
    }
}

/// Extract a string field from a JSON object.
pub fn json_str(value: &Value, field: &str) -> String {
    match value.get(field).and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => String::new(),
    }
}

/// Extract a bool field from a JSON object, defaulting to false.
pub fn json_bool(value: &Value, field: &str) -> bool {
    matches!(value.get(field).and_then(|v| v.as_bool()), Some(true))
}

/// Extract an i32 field from a JSON object, defaulting to zero.
pub fn json_i32(value: &Value, field: &str) -> i32 {
    value
        .get(field)
        .and_then(|v| v.as_i64())
        .and_then(|v| i32::try_from(v).ok())
        .into_iter()
        .sum()
}

/// Extract an i64 field from a JSON object, defaulting to zero.
pub fn json_i64(value: &Value, field: &str) -> i64 {
    value.get(field).and_then(|v| v.as_i64()).into_iter().sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_timestamp_valid_rfc3339() {
        let ts = parse_timestamp("2025-06-28T12:00:00Z").unwrap();
        assert!(ts.seconds > 0);
        assert_eq!(ts.nanos, 0);
    }

    #[test]
    fn parse_timestamp_invalid_returns_none() {
        assert!(parse_timestamp("not-a-date").is_none());
    }

    #[test]
    fn json_to_struct_accepts_object() {
        let value = json!({ "key": "value", "num": 1 });
        let s = json_to_struct(value).unwrap();
        assert!(s.fields.contains_key("key"));
    }

    #[test]
    fn json_to_struct_rejects_non_object() {
        assert!(json_to_struct(json!("string")).is_none());
        assert!(json_to_struct(json!([1, 2])).is_none());
    }

    #[test]
    fn json_array_to_strings_maps_mixed_types() {
        let value = json!(["a", 1, true, { "k": "v" }]);
        let out = json_array_to_strings(&value);
        assert_eq!(out, vec!["a", "1", "true", r#"{"k":"v"}"#]);
    }

    #[test]
    fn json_array_to_strings_non_array_defaults() {
        assert!(json_array_to_strings(&json!("x")).is_empty());
    }

    #[test]
    fn json_value_to_string_returns_string_unchanged() {
        assert_eq!(json_value_to_string(&json!("hello")), "hello");
    }

    #[test]
    fn json_value_to_string_serializes_non_strings() {
        assert_eq!(json_value_to_string(&json!(42)), "42");
        assert_eq!(json_value_to_string(&json!(null)), "null");
    }

    #[test]
    fn json_str_extracts_or_defaults() {
        assert_eq!(json_str(&json!({ "name": "Ada" }), "name"), "Ada");
        assert_eq!(json_str(&json!({}), "name"), "");
    }

    #[test]
    fn json_bool_extracts_or_defaults() {
        assert!(json_bool(&json!({ "active": true }), "active"));
        assert!(!json_bool(&json!({ "active": "yes" }), "active"));
        assert!(!json_bool(&json!({}), "active"));
    }

    #[test]
    fn json_i32_extracts_or_defaults() {
        assert_eq!(json_i32(&json!({ "n": 7 }), "n"), 7);
        assert_eq!(json_i32(&json!({ "n": i64::MAX }), "n"), 0);
        assert_eq!(json_i32(&json!({}), "n"), 0);
    }

    #[test]
    fn json_i64_extracts_or_defaults() {
        assert_eq!(json_i64(&json!({ "n": -99 }), "n"), -99);
        assert_eq!(json_i64(&json!({}), "n"), 0);
    }
}
