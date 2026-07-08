//! Thin internal clients for Ory Hydra, Kratos, and Keto.

pub mod error;
pub mod hydra;
#[cfg(feature = "keto")]
pub mod keto;
pub mod kratos;

pub use hydra::HydraClient;
#[cfg(feature = "keto")]
pub use keto::KetoClient;
pub use kratos::KratosClient;
