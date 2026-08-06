// SSO-027: tests may unwrap/expect freely; the panic/default bans target production code.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)
)]
use sso_gateway::config::Config;
use sunbeam_g2v::error::ServiceResult;

#[tokio::main]
async fn main() -> ServiceResult<()> {
    tracing_subscriber::fmt::init();

    let config = Config::from_env()
        .map_err(|e| sunbeam_g2v::error::ServiceError::Configuration(e.to_string()))?;

    sso_gateway::app::run(config).await
}
