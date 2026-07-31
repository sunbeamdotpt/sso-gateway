//! Generated Connect-RPC/protobuf code.
//!
//! The generated view code uses `Result::unwrap_or_default`, which is banned
//! workspace-wide (SSO-027). That call site is owned by the connectrpc-build
//! generator and must be fixed upstream rather than edited here, so the lint
//! is suppressed for this module only.
#![allow(clippy::disallowed_methods)]

connectrpc::include_generated!();
