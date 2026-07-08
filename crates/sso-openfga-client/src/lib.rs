//! Thin internal client for OpenFGA.

pub mod client;
pub mod error;

pub use client::{OpenFgaClient, WriteTupleOp};
pub use error::OpenFgaClientError;
