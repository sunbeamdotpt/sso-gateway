// SSO-027: tests may unwrap/expect freely; the panic/default bans target production code.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods))]
//! Thin internal client for OpenFGA.

pub mod client;
pub mod error;

pub use client::{OpenFgaClient, RequestOptions, TupleKey, WriteTupleOp, flat_model};
pub use error::OpenFgaClientError;
