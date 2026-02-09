#![doc = include_str!("../README.md")]
//!
//! # 모듈 구성
//!
//! - [`collector`]: 다양한 소스에서 원시 로그 수집 (파일, syslog UDP/TCP, eBPF 이벤트)
//! - [`parser`]: Syslog RFC 5424, JSON 등 형식별 파서 및 자동 감지 라우터
//! - [`rule`]: YAML 기반 탐지 규칙 엔진 (간소화된 Sigma 스타일)
//! - [`buffer`]: 인메모리 로그 버퍼링 및 배치 플러시
//! - [`alert`]: 알림 생성, 중복 제거, 속도 제한
//! - [`pipeline`]: 전체 파이프라인 오케스트레이션 (Pipeline trait 구현)
//! - [`config`]: 파이프라인 설정 (core 설정 확장)
//! - [`error`]: 도메인 에러 타입
//!
//! # 아키텍처
//!
//! ```text
//! Collectors -> Buffer -> ParserRouter -> RuleEngine -> AlertGenerator -> downstream
//!     |                    |                |               |
//!  File/Syslog/eBPF    Syslog/JSON      YAML rules     Dedup + Rate limit
//! ```

pub mod alert;
pub mod buffer;
pub mod config;
pub mod error;
pub mod pipeline;

pub mod collector;
pub mod parser;
pub mod rule;

// --- 주요 타입 re-export ---

// 파이프라인
pub use pipeline::{LogPipeline, LogPipelineBuilder};

// 설정
pub use config::{DropPolicy, PipelineConfig, PipelineConfigBuilder};

// 에러
pub use error::LogPipelineError;

// 파서
pub use parser::{JsonLogParser, ParserRouter, SyslogParser};

// 규칙 엔진
pub use rule::{DetectionRule, RuleEngine, RuleMatch};

// 수집기
pub use collector::{CollectorSet, RawLog};

// 알림
pub use alert::AlertGenerator;

// 버퍼
pub use buffer::LogBuffer;
