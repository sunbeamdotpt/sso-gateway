use sso_gateway::config::Config;
use sunbeam_g2v::error::ServiceResult;

#[tokio::main]
async fn main() -> ServiceResult<()> {
    tracing_subscriber::fmt::init();

    let config = Config::from_env()
        .map_err(|e| sunbeam_g2v::error::ServiceError::Configuration(e.to_string()))?;

    sso_gateway::app::run(config).await
}
