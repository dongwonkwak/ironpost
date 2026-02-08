//! eBPF 엔진 설정 — 필터링 룰 관리 및 동적 업데이트
//!
//! [`EngineConfig`]는 core의 [`EbpfConfig`]를 확장하여 필터링 룰을 관리합니다.
//! 런타임에 룰을 동적으로 추가/삭제하면 eBPF HashMap 맵이 업데이트됩니다.
//!
//! # 설정 예시 (TOML)
//! ```toml
//! [[rules]]
//! id = "block-scanner"
//! src_ip = "10.0.0.50"
//! action = "block"
//! description = "Known port scanner"
//!
//! [[rules]]
//! id = "monitor-suspicious"
//! src_ip = "192.168.1.100"
//! action = "monitor"
//! description = "Suspicious internal host"
//! ```

use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use ironpost_core::config::EbpfConfig;
use ironpost_core::error::IronpostError;

/// 필터링 룰 액션
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    /// 패킷 차단 (XDP_DROP)
    Block,
    /// 패킷 통과 + 모니터링 이벤트 전송
    Monitor,
}

/// 네트워크 필터링 룰
///
/// IP/포트/프로토콜 조합으로 차단 또는 모니터링 대상을 지정합니다.
/// `None` 필드는 "모든 값"을 의미합니다 (와일드카드).
///
/// # eBPF HashMap 매핑
/// 현재 eBPF HashMap 키는 `u32` (IPv4 주소)이므로,
/// `src_ip`가 설정된 룰만 커널 맵에 반영됩니다.
/// 포트/프로토콜 필터링은 유저스페이스에서 보조 처리합니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRule {
    /// 규칙 고유 ID
    pub id: String,
    /// 출발지 IP (None이면 모든 IP)
    pub src_ip: Option<IpAddr>,
    /// 목적지 IP (None이면 모든 IP)
    pub dst_ip: Option<IpAddr>,
    /// 목적지 포트 (None이면 모든 포트)
    pub dst_port: Option<u16>,
    /// 프로토콜 (None이면 모든 프로토콜, 6=TCP, 17=UDP)
    pub protocol: Option<u8>,
    /// 적용할 액션
    pub action: RuleAction,
    /// 규칙 설명
    pub description: String,
}

/// eBPF 엔진 확장 설정
///
/// core의 [`EbpfConfig`]를 기반으로 필터링 룰을 추가합니다.
/// `from_core()`로 core 설정에서 생성하고, `load_rules()`로 TOML 파일에서
/// 룰을 로드합니다.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EngineConfig {
    /// core에서 가져온 기본 설정 (interface, xdp_mode, ring_buffer_size 등)
    #[serde(flatten)]
    pub base: EbpfConfig,
    /// 필터링 룰 목록
    #[serde(default)]
    pub rules: Vec<FilterRule>,
}

/// TOML 룰 파일의 최상위 구조
#[derive(Debug, Clone, Deserialize)]
struct RulesFile {
    #[serde(default)]
    rules: Vec<FilterRule>,
}

impl EngineConfig {
    /// core EbpfConfig에서 엔진 설정을 생성합니다 (룰 없이).
    pub fn from_core(config: &EbpfConfig) -> Self {
        Self {
            base: config.clone(),
            rules: Vec::new(),
        }
    }

    /// TOML 파일에서 필터링 룰을 로드합니다.
    ///
    /// 파일이 존재하지 않으면 빈 Vec을 반환합니다.
    pub async fn load_rules(path: impl AsRef<Path>) -> Result<Vec<FilterRule>, IronpostError> {
        todo!("TOML 파일에서 FilterRule Vec 로드")
    }

    /// 룰을 추가합니다.
    ///
    /// 동일한 ID의 룰이 이미 존재하면 교체합니다.
    pub fn add_rule(&mut self, rule: FilterRule) {
        self.rules.retain(|r| r.id != rule.id);
        self.rules.push(rule);
    }

    /// 룰을 ID로 제거합니다.
    ///
    /// 제거된 경우 `true`, 존재하지 않으면 `false`를 반환합니다.
    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != rule_id);
        self.rules.len() < before
    }

    /// src_ip가 설정된 차단/모니터링 룰을 반환합니다.
    ///
    /// eBPF HashMap에 반영 가능한 룰만 필터링합니다.
    pub fn ip_rules(&self) -> impl Iterator<Item = &FilterRule> {
        self.rules.iter().filter(|r| r.src_ip.is_some())
    }
}
