//! Thin internal clients for Ory Hydra, Kratos, and Keto.

pub mod error;
pub mod hydra;
pub mod keto;
pub mod kratos;

pub use hydra::HydraClient;
pub use keto::KetoClient;
pub use kratos::KratosClient;
