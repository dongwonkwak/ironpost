//! 컨테이너 이벤트 — Docker 컨테이너 생명주기 이벤트
//!
//! [`ContainerEvent`]는 Docker 컨테이너의 생성/시작/정지/삭제 등
//! 생명주기 이벤트를 나타냅니다. core의 [`Event`] trait을 구현합니다.

use std::fmt;

use serde::{Deserialize, Serialize};

use ironpost_core::event::{EVENT_TYPE_ACTION, Event, EventMetadata, MODULE_CONTAINER_GUARD};

/// 컨테이너 생명주기 이벤트 종류
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerEventKind {
    /// 컨테이너 생성됨
    Created,
    /// 컨테이너 시작됨
    Started,
    /// 컨테이너 정지됨
    Stopped,
    /// 컨테이너 삭제됨
    Deleted,
    /// 컨테이너 일시정지됨
    Paused,
    /// 컨테이너 일시정지 해제됨
    Unpaused,
    /// 네트워크에서 연결 해제됨
    NetworkDisconnected {
        /// 연결 해제된 네트워크명
        network: String,
    },
}

impl fmt::Display for ContainerEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Started => write!(f, "started"),
            Self::Stopped => write!(f, "stopped"),
            Self::Deleted => write!(f, "deleted"),
            Self::Paused => write!(f, "paused"),
            Self::Unpaused => write!(f, "unpaused"),
            Self::NetworkDisconnected { network } => {
                write!(f, "network_disconnected({network})")
            }
        }
    }
}

/// Docker 컨테이너 생명주기 이벤트
///
/// Docker 데몬에서 발생하는 컨테이너 이벤트를 나타냅니다.
/// 모니터링 모듈에서 감시하여 컨테이너 인벤토리를 유지합니다.
#[derive(Debug, Clone)]
pub struct ContainerEvent {
    /// 이벤트 고유 ID
    pub id: String,
    /// 이벤트 메타데이터
    pub metadata: EventMetadata,
    /// 대상 컨테이너 ID
    pub container_id: String,
    /// 대상 컨테이너 이름
    pub container_name: String,
    /// 이벤트 종류
    pub event_kind: ContainerEventKind,
}

impl ContainerEvent {
    /// 새로운 trace를 시작하는 컨테이너 이벤트를 생성합니다.
    pub fn new(
        container_id: impl Into<String>,
        container_name: impl Into<String>,
        event_kind: ContainerEventKind,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            metadata: EventMetadata::with_new_trace(MODULE_CONTAINER_GUARD),
            container_id: container_id.into(),
            container_name: container_name.into(),
            event_kind,
        }
    }

    /// 기존 trace에 연결된 컨테이너 이벤트를 생성합니다.
    pub fn with_trace(
        container_id: impl Into<String>,
        container_name: impl Into<String>,
        event_kind: ContainerEventKind,
        trace_id: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            metadata: EventMetadata::new(MODULE_CONTAINER_GUARD, trace_id),
            container_id: container_id.into(),
            container_name: container_name.into(),
            event_kind,
        }
    }
}

impl Event for ContainerEvent {
    fn event_id(&self) -> &str {
        &self.id
    }

    fn metadata(&self) -> &EventMetadata {
        &self.metadata
    }

    fn event_type(&self) -> &str {
        EVENT_TYPE_ACTION
    }
}

impl fmt::Display for ContainerEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ContainerEvent[{}] container={} ({}) kind={}",
            &self.id[..8.min(self.id.len())],
            self.container_name,
            &self.container_id[..12.min(self.container_id.len())],
            self.event_kind,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_event_kind_display() {
        assert_eq!(ContainerEventKind::Created.to_string(), "created");
        assert_eq!(ContainerEventKind::Started.to_string(), "started");
        assert_eq!(ContainerEventKind::Stopped.to_string(), "stopped");
        assert_eq!(ContainerEventKind::Deleted.to_string(), "deleted");
        assert_eq!(ContainerEventKind::Paused.to_string(), "paused");
        assert_eq!(ContainerEventKind::Unpaused.to_string(), "unpaused");
        assert_eq!(
            ContainerEventKind::NetworkDisconnected {
                network: "bridge".to_owned()
            }
            .to_string(),
            "network_disconnected(bridge)"
        );
    }

    #[test]
    fn container_event_implements_event_trait() {
        let event = ContainerEvent::new("abc123def456", "web-server", ContainerEventKind::Started);
        assert_eq!(event.event_type(), "action");
        assert!(!event.event_id().is_empty());
        assert_eq!(event.metadata().source_module, "container-guard");
    }

    #[test]
    fn container_event_with_trace_preserves_trace_id() {
        let event = ContainerEvent::with_trace(
            "abc123",
            "web-server",
            ContainerEventKind::Paused,
            "my-trace-id",
        );
        assert_eq!(event.metadata().trace_id, "my-trace-id");
    }

    #[test]
    fn container_event_display() {
        let event = ContainerEvent::new("abc123def456", "web-server", ContainerEventKind::Stopped);
        let display = event.to_string();
        assert!(display.contains("ContainerEvent"));
        assert!(display.contains("web-server"));
        assert!(display.contains("stopped"));
    }

    #[test]
    fn container_event_is_send_sync() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<ContainerEvent>();
    }

    #[test]
    fn container_event_kind_equality() {
        assert_eq!(ContainerEventKind::Created, ContainerEventKind::Created);
        assert_ne!(ContainerEventKind::Created, ContainerEventKind::Started);
        assert_eq!(
            ContainerEventKind::NetworkDisconnected {
                network: "bridge".to_owned()
            },
            ContainerEventKind::NetworkDisconnected {
                network: "bridge".to_owned()
            }
        );
    }
}
