#![doc = include_str!("../README.md")]

pub mod config;
pub mod error;
pub mod event;
pub mod pipeline;
pub mod types;

// --- 주요 타입 re-export ---
// 각 모듈의 핵심 타입을 크레이트 루트에서 바로 사용할 수 있도록 합니다.

// 에러
pub use error::{
    ConfigError, ContainerError, DetectionError, IronpostError, ParseError, PipelineError,
    SbomError, StorageError,
};

// 설정
pub use config::IronpostConfig;

// 이벤트
pub use event::{
    ActionEvent, AlertEvent, EVENT_TYPE_ACTION, EVENT_TYPE_ALERT, EVENT_TYPE_LOG,
    EVENT_TYPE_PACKET, EVENT_TYPE_SCAN, Event, EventMetadata, LogEvent,
    MODULE_CONTAINER_GUARD, MODULE_EBPF, MODULE_LOG_PIPELINE, MODULE_SBOM_SCANNER, PacketEvent,
};

// 파이프라인 trait
pub use pipeline::{
    BoxFuture, Detector, DynPipeline, HealthStatus, LogParser, Pipeline, PolicyEnforcer,
};

// 도메인 타입
pub use types::{Alert, ContainerInfo, LogEntry, PacketInfo, Severity, Vulnerability};
