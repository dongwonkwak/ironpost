#![doc = include_str!("../README.md")]
//!
//! # 모듈 구성
//! - [`config`]: 필터링 룰 관리 + core 설정 확장
//! - [`engine`]: EbpfEngine — XDP 프로그램 로드/관리, Pipeline trait 구현
//! - [`stats`]: 프로토콜별 트래픽 통계 (PerCpuArray 기반)
//! - [`detector`]: SYN flood / 포트 스캔 이상 탐지 (Detector trait 구현)
//!
//! # 공유 타입
//! 커널/유저스페이스 공유 타입은 [`ironpost_ebpf_common`] 크레이트에 정의되어 있습니다.

pub mod config;
pub mod detector;
pub mod engine;
pub mod stats;

// --- 주요 타입 re-export ---

// 엔진
pub use engine::{EbpfEngine, EbpfEngineBuilder};

// 설정
pub use config::{EngineConfig, FilterRule, RuleAction};

// 통계
pub use stats::{ProtoMetrics, RawProtoStats, RawTrafficSnapshot, TrafficStats};

// 탐지
pub use detector::{
    PacketDetector, PortScanConfig, PortScanDetector, SynFloodConfig, SynFloodDetector,
};

// 공유 타입 (커널/유저스페이스 공통)
pub use ironpost_ebpf_common;
