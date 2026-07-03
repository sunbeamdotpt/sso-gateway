//! Public HTTP handlers for protocol-mandated endpoints.
//!
//! These modules are kept separate from Connect-RPC service implementations
//! because they deal with browser redirects, form posts, and other HTTP-only
//! concerns required by OAuth 2.0, OIDC, SAML 2.0, and SCIM 2.0.

pub mod callback;
pub mod oauth2;
pub mod saml;
pub mod saml_idp;
pub mod scim;
pub mod self_service;
