//! 파이프라인 trait — 모듈 확장 포인트 정의

use crate::error::IronpostError;
use crate::types::{Alert, LogEntry};

/// 탐지 로직을 구현하는 trait
///
/// 새로운 탐지 규칙을 추가하려면 이 trait을 구현합니다.
pub trait Detector: Send + Sync {
    /// 탐지기 이름
    fn name(&self) -> &str;

    /// 이벤트를 분석하여 알림 생성 여부를 결정
    fn detect(&self, entry: &LogEntry) -> Result<Option<Alert>, IronpostError>;
}

/// 로그 파서 trait
///
/// 새로운 로그 형식을 지원하려면 이 trait을 구현합니다.
pub trait LogParser: Send + Sync {
    /// 지원하는 로그 형식 이름
    fn format_name(&self) -> &str;

    /// 원시 바이트를 로그 엔트리로 파싱
    fn parse(&self, raw: &[u8]) -> Result<LogEntry, IronpostError>;
}

/// 격리 정책을 구현하는 trait
pub trait PolicyEnforcer: Send + Sync {
    /// 정책 이름
    fn name(&self) -> &str;

    /// 알림에 대해 격리 실행 여부를 결정하고, 필요 시 격리를 수행
    fn enforce(&self, alert: &Alert) -> Result<bool, IronpostError>;
}
