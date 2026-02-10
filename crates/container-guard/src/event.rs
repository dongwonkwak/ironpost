//! Container lifecycle events.
//!
//! [`ContainerEvent`] represents Docker container lifecycle events such as
//! creation, start, stop, pause, and network disconnection.
//!
//! These events implement core's [`Event`] trait and are emitted by the
//! [`IsolationExecutor`](crate::isolation::IsolationExecutor) as [`ActionEvent`](ironpost_core::event::ActionEvent)
//! messages after isolation actions complete.
//!
//! # Examples
//!
//! ```
//! use ironpost_container_guard::{ContainerEvent, ContainerEventKind};
//!
//! // Create a new event with a new trace
//! let event = ContainerEvent::new(
//!     "abc123def456",
//!     "web-server",
//!     ContainerEventKind::Paused,
//! );
//!
//! // Or link to an existing trace from an alert
//! let event_with_trace = ContainerEvent::with_trace(
//!     "abc123def456",
//!     "web-server",
//!     ContainerEventKind::NetworkDisconnected {
//!         network: "bridge".to_owned(),
//!     },
//!     "trace-123",
//! );
//! ```

use std::fmt;

use serde::{Deserialize, Serialize};

use ironpost_core::event::{EVENT_TYPE_ACTION, Event, EventMetadata, MODULE_CONTAINER_GUARD};

/// Container lifecycle event kind.
///
/// Represents the type of lifecycle event that occurred on a Docker container.
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

/// Docker container lifecycle event.
///
/// Represents a container event from the Docker daemon. These events are
/// monitored by [`DockerMonitor`](crate::monitor::DockerMonitor) to maintain
/// the container inventory.
///
/// # Event Metadata
///
/// Each event carries `EventMetadata` which includes:
/// - `source_module`: Always `"container-guard"`
/// - `trace_id`: Links related events across modules
/// - `timestamp`: Event creation time
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
    /// Creates a container event with a new trace ID.
    ///
    /// Use this when the event is not part of an existing trace (e.g., standalone container monitoring).
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

    /// Creates a container event linked to an existing trace.
    ///
    /// Use this to connect the container event to an upstream trace, such as
    /// linking an isolation action back to the original alert that triggered it.
    ///
    /// # Arguments
    ///
    /// - `trace_id`: Trace ID from the originating event (e.g., `AlertEvent.metadata.trace_id`)
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
