use connectrpc::ConnectError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("missing system tenant")]
    MissingSystemTenant,

    #[error("tenant not found")]
    TenantNotFound,

    #[error("id mapping not found")]
    MappingNotFound,

    #[error("identity schema not found")]
    SchemaNotFound,

    #[error("tenant membership not found")]
    MembershipNotFound,

    #[error("permission tuple not found")]
    TupleNotFound,

    #[error("saml provider not found")]
    SamlProviderNotFound,

    #[error("saml request not found")]
    SamlRequestNotFound,

    #[error("saml request replay detected")]
    SamlRequestReplay,

    #[error("saml identity mapping not found")]
    SamlIdentityMappingNotFound,

    #[error("saml nameid mapping not found")]
    SamlNameIdMappingNotFound,

    #[error("encryption key missing or invalid")]
    EncryptionKeyMissing,

    #[error("saml idp key not found")]
    SamlIdpKeyNotFound,

    #[error("saml service provider client not found")]
    SamlSpClientNotFound,

    #[error("api key not found or expired")]
    ApiKeyNotFound,

    #[error("connection not found")]
    ConnectionNotFound,

    #[error("local auth method not found")]
    LocalAuthNotFound,

    #[error("domain not found")]
    DomainNotFound,

    #[error("domain not verified")]
    DomainNotVerified,

    #[error("login state not found or expired")]
    LoginStateNotFound,

    #[error("invalid connection type: {0}")]
    InvalidConnectionType(String),

    #[error("invalid local auth method: {0}")]
    InvalidLocalAuthMethod(String),
}

impl From<DbError> for sunbeam_g2v::error::ServiceError {
    fn from(err: DbError) -> Self {
        match err {
            DbError::Sqlx(e) => Self::Database(e.to_string()),
            DbError::MissingSystemTenant => Self::Internal("missing system tenant".to_string()),
            DbError::TenantNotFound => Self::NotFound("tenant not found".to_string()),
            DbError::MappingNotFound => Self::NotFound("id mapping not found".to_string()),
            DbError::SchemaNotFound => Self::NotFound("identity schema not found".to_string()),
            DbError::MembershipNotFound => {
                Self::NotFound("tenant membership not found".to_string())
            }
            DbError::TupleNotFound => Self::NotFound("permission tuple not found".to_string()),
            DbError::SamlProviderNotFound => Self::NotFound("saml provider not found".to_string()),
            DbError::SamlRequestNotFound => Self::NotFound("saml request not found".to_string()),
            DbError::SamlRequestReplay => {
                Self::InvalidArgument("saml request replay detected".to_string())
            }
            DbError::SamlIdentityMappingNotFound => {
                Self::NotFound("saml identity mapping not found".to_string())
            }
            DbError::SamlNameIdMappingNotFound => {
                Self::NotFound("saml nameid mapping not found".to_string())
            }
            DbError::EncryptionKeyMissing => {
                Self::Configuration("encryption key missing or invalid".to_string())
            }
            DbError::SamlIdpKeyNotFound => Self::NotFound("saml idp key not found".to_string()),
            DbError::SamlSpClientNotFound => {
                Self::NotFound("saml service provider client not found".to_string())
            }
            DbError::ApiKeyNotFound => {
                Self::Unauthenticated("api key not found or expired".to_string())
            }
            DbError::ConnectionNotFound => Self::NotFound("connection not found".to_string()),
            DbError::LocalAuthNotFound => Self::NotFound("local auth method not found".to_string()),
            DbError::DomainNotFound => Self::NotFound("domain not found".to_string()),
            DbError::DomainNotVerified => Self::NotFound("domain not verified".to_string()),
            DbError::LoginStateNotFound => {
                Self::NotFound("login state not found or expired".to_string())
            }
            DbError::InvalidConnectionType(s) => {
                Self::InvalidArgument(format!("invalid connection type: {s}"))
            }
            DbError::InvalidLocalAuthMethod(s) => {
                Self::InvalidArgument(format!("invalid local auth method: {s}"))
            }
        }
    }
}

impl From<DbError> for ConnectError {
    fn from(err: DbError) -> Self {
        let service_err: sunbeam_g2v::error::ServiceError = err.into();
        service_err.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sunbeam_g2v::error::ServiceError;

    #[test]
    fn db_error_into_service_error_maps_all_variants() {
        let cases: Vec<(DbError, ServiceError)> = vec![
            (
                DbError::Sqlx(sqlx::Error::PoolTimedOut),
                ServiceError::Database("sqlx error: PoolTimedOut".into()),
            ),
            (
                DbError::MissingSystemTenant,
                ServiceError::Internal("missing system tenant".into()),
            ),
            (
                DbError::TenantNotFound,
                ServiceError::NotFound("tenant not found".into()),
            ),
            (
                DbError::MappingNotFound,
                ServiceError::NotFound("id mapping not found".into()),
            ),
            (
                DbError::SchemaNotFound,
                ServiceError::NotFound("identity schema not found".into()),
            ),
            (
                DbError::MembershipNotFound,
                ServiceError::NotFound("tenant membership not found".into()),
            ),
            (
                DbError::TupleNotFound,
                ServiceError::NotFound("permission tuple not found".into()),
            ),
            (
                DbError::SamlProviderNotFound,
                ServiceError::NotFound("saml provider not found".into()),
            ),
            (
                DbError::SamlRequestNotFound,
                ServiceError::NotFound("saml request not found".into()),
            ),
            (
                DbError::SamlRequestReplay,
                ServiceError::InvalidArgument("saml request replay detected".into()),
            ),
            (
                DbError::SamlIdentityMappingNotFound,
                ServiceError::NotFound("saml identity mapping not found".into()),
            ),
            (
                DbError::SamlNameIdMappingNotFound,
                ServiceError::NotFound("saml nameid mapping not found".into()),
            ),
            (
                DbError::EncryptionKeyMissing,
                ServiceError::Configuration("encryption key missing or invalid".into()),
            ),
            (
                DbError::SamlIdpKeyNotFound,
                ServiceError::NotFound("saml idp key not found".into()),
            ),
            (
                DbError::SamlSpClientNotFound,
                ServiceError::NotFound("saml service provider client not found".into()),
            ),
            (
                DbError::ApiKeyNotFound,
                ServiceError::Unauthenticated("api key not found or expired".into()),
            ),
            (
                DbError::ConnectionNotFound,
                ServiceError::NotFound("connection not found".into()),
            ),
            (
                DbError::LocalAuthNotFound,
                ServiceError::NotFound("local auth method not found".into()),
            ),
            (
                DbError::DomainNotFound,
                ServiceError::NotFound("domain not found".into()),
            ),
            (
                DbError::DomainNotVerified,
                ServiceError::NotFound("domain not verified".into()),
            ),
            (
                DbError::LoginStateNotFound,
                ServiceError::NotFound("login state not found or expired".into()),
            ),
            (
                DbError::InvalidConnectionType("foo".to_string()),
                ServiceError::InvalidArgument("invalid connection type: foo".into()),
            ),
            (
                DbError::InvalidLocalAuthMethod("bar".to_string()),
                ServiceError::InvalidArgument("invalid local auth method: bar".into()),
            ),
        ];
        for (err, expected) in cases {
            let actual: ServiceError = err.into();
            assert_eq!(
                std::mem::discriminant(&actual),
                std::mem::discriminant(&expected)
            );
        }
    }

    #[test]
    fn db_error_into_connect_error_round_trips() {
        let err = DbError::TenantNotFound;
        let connect_err: ConnectError = err.into();
        assert_eq!(connect_err.code, connectrpc::ErrorCode::NotFound);
    }
}
