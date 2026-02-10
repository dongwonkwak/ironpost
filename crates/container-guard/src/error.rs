//! Container guard error types.
//!
//! [`ContainerGuardError`] represents all errors that can occur within the container guard module.
//! It implements `From<ContainerGuardError> for IronpostError`, allowing natural error propagation
//! with the `?` operator in upstream code.
//!
//! # Error Categories
//!
//! - **Docker API errors**: `DockerApi`, `DockerConnection`
//! - **Isolation failures**: `IsolationFailed`, `ContainerNotFound`
//! - **Policy errors**: `PolicyLoad`, `PolicyValidation`
//! - **Configuration errors**: `Config`
//! - **Channel errors**: `Channel`
//!
//! # Examples
//!
//! ```
//! # use ironpost_container_guard::ContainerGuardError;
//! # use ironpost_core::error::IronpostError;
//! fn example() -> Result<(), ContainerGuardError> {
//!     // Docker API error
//!     Err(ContainerGuardError::DockerApi("connection refused".to_owned()))?;
//!     Ok(())
//! }
//!
//! // Automatically converts to IronpostError
//! fn upstream() -> Result<(), IronpostError> {
//!     example()?;
//!     Ok(())
//! }
//! ```

use ironpost_core::error::{ContainerError, IronpostError};

/// Domain-specific errors for container guard operations.
///
/// Covers all error scenarios within the container guard module, including
/// Docker API failures, isolation execution errors, policy loading/validation,
/// and configuration issues.
///
/// # Error Conversion
///
/// This type implements `From<ContainerGuardError> for IronpostError`, allowing
/// seamless propagation to the top-level error type used by `ironpost-daemon`.
#[derive(Debug, thiserror::Error)]
pub enum ContainerGuardError {
    /// Docker API 호출 실패
    #[error("docker api error: {0}")]
    DockerApi(String),

    /// Docker 소켓 연결 실패
    #[error("docker connection error: {0}")]
    DockerConnection(String),

    /// 컨테이너 격리 실패
    #[error("isolation failed for container '{container_id}': {reason}")]
    IsolationFailed {
        /// 대상 컨테이너 ID
        container_id: String,
        /// 격리 실패 사유
        reason: String,
    },

    /// 정책 파일 로딩 실패
    #[error("policy load error: {path}: {reason}")]
    PolicyLoad {
        /// 정책 파일 경로
        path: String,
        /// 로딩 실패 사유
        reason: String,
    },

    /// 정책 유효성 검증 실패
    #[error("policy validation error: policy '{policy_id}': {reason}")]
    PolicyValidation {
        /// 문제가 된 정책 ID
        policy_id: String,
        /// 검증 실패 사유
        reason: String,
    },

    /// 컨테이너를 찾을 수 없음
    #[error("container not found: {0}")]
    ContainerNotFound(String),

    /// 잘못된 컨테이너 ID
    #[error("invalid container id: {0}")]
    InvalidContainerId(String),

    /// 설정 에러
    #[error("config error: {field}: {reason}")]
    Config {
        /// 설정 필드명
        field: String,
        /// 에러 사유
        reason: String,
    },

    /// 채널 통신 에러
    #[error("channel error: {0}")]
    Channel(String),
}

impl From<ContainerGuardError> for IronpostError {
    fn from(err: ContainerGuardError) -> Self {
        match &err {
            ContainerGuardError::DockerApi(msg) => {
                IronpostError::Container(ContainerError::DockerApi(msg.clone()))
            }
            ContainerGuardError::DockerConnection(msg) => {
                IronpostError::Container(ContainerError::DockerApi(msg.clone()))
            }
            ContainerGuardError::IsolationFailed {
                container_id,
                reason,
            } => IronpostError::Container(ContainerError::IsolationFailed {
                container_id: container_id.clone(),
                reason: reason.clone(),
            }),
            ContainerGuardError::ContainerNotFound(id) => {
                IronpostError::Container(ContainerError::NotFound(id.clone()))
            }
            ContainerGuardError::InvalidContainerId(msg) => IronpostError::Container(
                ContainerError::DockerApi(format!("invalid container id: {}", msg)),
            ),
            ContainerGuardError::PolicyLoad { .. }
            | ContainerGuardError::PolicyValidation { .. } => {
                IronpostError::Container(ContainerError::PolicyViolation(err.to_string()))
            }
            ContainerGuardError::Config { .. } | ContainerGuardError::Channel(_) => {
                IronpostError::Container(ContainerError::DockerApi(err.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_api_error_display() {
        let err = ContainerGuardError::DockerApi("connection refused".to_owned());
        assert!(err.to_string().contains("connection refused"));
    }

    #[test]
    fn docker_connection_error_display() {
        let err = ContainerGuardError::DockerConnection("socket not found".to_owned());
        assert!(err.to_string().contains("socket not found"));
    }

    #[test]
    fn isolation_failed_display() {
        let err = ContainerGuardError::IsolationFailed {
            container_id: "abc123".to_owned(),
            reason: "network disconnect failed".to_owned(),
        };
        let msg = err.to_string();
        assert!(msg.contains("abc123"));
        assert!(msg.contains("network disconnect failed"));
    }

    #[test]
    fn policy_load_error_display() {
        let err = ContainerGuardError::PolicyLoad {
            path: "/etc/ironpost/policies/test.toml".to_owned(),
            reason: "invalid TOML".to_owned(),
        };
        assert!(err.to_string().contains("test.toml"));
    }

    #[test]
    fn policy_validation_error_display() {
        let err = ContainerGuardError::PolicyValidation {
            policy_id: "policy-001".to_owned(),
            reason: "missing action".to_owned(),
        };
        let msg = err.to_string();
        assert!(msg.contains("policy-001"));
        assert!(msg.contains("missing action"));
    }

    #[test]
    fn container_not_found_display() {
        let err = ContainerGuardError::ContainerNotFound("xyz789".to_owned());
        assert!(err.to_string().contains("xyz789"));
    }

    #[test]
    fn config_error_display() {
        let err = ContainerGuardError::Config {
            field: "poll_interval_secs".to_owned(),
            reason: "must be greater than 0".to_owned(),
        };
        let msg = err.to_string();
        assert!(msg.contains("poll_interval_secs"));
        assert!(msg.contains("must be greater than 0"));
    }

    #[test]
    fn channel_error_display() {
        let err = ContainerGuardError::Channel("receiver dropped".to_owned());
        assert!(err.to_string().contains("receiver dropped"));
    }

    #[test]
    fn converts_to_ironpost_error_docker_api() {
        let err = ContainerGuardError::DockerApi("test".to_owned());
        let ironpost_err: IronpostError = err.into();
        assert!(matches!(ironpost_err, IronpostError::Container(_)));
    }

    #[test]
    fn converts_to_ironpost_error_isolation_failed() {
        let err = ContainerGuardError::IsolationFailed {
            container_id: "abc".to_owned(),
            reason: "test".to_owned(),
        };
        let ironpost_err: IronpostError = err.into();
        assert!(matches!(
            ironpost_err,
            IronpostError::Container(ContainerError::IsolationFailed { .. })
        ));
    }

    #[test]
    fn converts_to_ironpost_error_not_found() {
        let err = ContainerGuardError::ContainerNotFound("xyz".to_owned());
        let ironpost_err: IronpostError = err.into();
        assert!(matches!(
            ironpost_err,
            IronpostError::Container(ContainerError::NotFound(_))
        ));
    }

    #[test]
    fn converts_to_ironpost_error_policy_violation() {
        let err = ContainerGuardError::PolicyValidation {
            policy_id: "p1".to_owned(),
            reason: "bad".to_owned(),
        };
        let ironpost_err: IronpostError = err.into();
        assert!(matches!(
            ironpost_err,
            IronpostError::Container(ContainerError::PolicyViolation(_))
        ));
    }
}
