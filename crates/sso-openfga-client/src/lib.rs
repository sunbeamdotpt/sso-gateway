//! Thin internal client for OpenFGA.

pub mod client;
pub mod error;

pub use client::{OpenFgaClient, RequestOptions, TupleKey, WriteTupleOp, flat_model};
pub use error::OpenFgaClientError;
