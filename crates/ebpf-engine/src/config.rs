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
        use ironpost_core::error::ConfigError;

        let path = path.as_ref();

        // 파일이 존재하지 않으면 빈 Vec 반환
        match tokio::fs::read_to_string(path).await {
            Ok(content) => {
                // TOML 파싱
                let rules_file: RulesFile =
                    toml::from_str(&content).map_err(|e| ConfigError::ParseFailed {
                        reason: format!("failed to parse rules file: {}", e),
                    })?;
                Ok(rules_file.rules)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // 파일이 없으면 빈 벡터 반환
                Ok(Vec::new())
            }
            Err(e) => {
                // 다른 I/O 에러는 전파
                Err(e.into())
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // =============================================================================
    // FilterRule 테스트
    // =============================================================================

    #[test]
    fn test_filter_rule_creation_with_defaults() {
        let rule = FilterRule {
            id: "test-rule".to_owned(),
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            protocol: None,
            action: RuleAction::Block,
            description: "Test rule".to_owned(),
        };

        assert_eq!(rule.id, "test-rule");
        assert!(rule.src_ip.is_none());
        assert!(rule.dst_ip.is_none());
        assert!(rule.dst_port.is_none());
        assert!(rule.protocol.is_none());
        assert_eq!(rule.action, RuleAction::Block);
    }

    #[test]
    fn test_filter_rule_with_all_fields() {
        let rule = FilterRule {
            id: "full-rule".to_owned(),
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            dst_port: Some(443),
            protocol: Some(6), // TCP
            action: RuleAction::Monitor,
            description: "Full rule with all fields".to_owned(),
        };

        assert_eq!(rule.id, "full-rule");
        assert!(rule.src_ip.is_some());
        assert!(rule.dst_ip.is_some());
        assert_eq!(rule.dst_port, Some(443));
        assert_eq!(rule.protocol, Some(6));
        assert_eq!(rule.action, RuleAction::Monitor);
    }

    #[test]
    fn test_rule_action_serde_roundtrip() {
        let block = RuleAction::Block;
        let monitor = RuleAction::Monitor;

        let block_json = serde_json::to_string(&block).unwrap();
        let monitor_json = serde_json::to_string(&monitor).unwrap();

        assert_eq!(block_json, r#""block""#);
        assert_eq!(monitor_json, r#""monitor""#);

        let deserialized_block: RuleAction = serde_json::from_str(&block_json).unwrap();
        let deserialized_monitor: RuleAction = serde_json::from_str(&monitor_json).unwrap();

        assert_eq!(deserialized_block, RuleAction::Block);
        assert_eq!(deserialized_monitor, RuleAction::Monitor);
    }

    // =============================================================================
    // EngineConfig 테스트
    // =============================================================================

    #[test]
    fn test_engine_config_from_core() {
        use ironpost_core::config::EbpfConfig;

        let ebpf_config = EbpfConfig {
            enabled: true,
            interface: "eth0".to_owned(),
            xdp_mode: "skb".to_owned(),
            ring_buffer_size: 1024,
            blocklist_max_entries: 10000,
        };

        let engine_config = EngineConfig::from_core(&ebpf_config);

        assert_eq!(engine_config.base.interface, "eth0");
        assert_eq!(engine_config.base.xdp_mode, "skb");
        assert_eq!(engine_config.base.ring_buffer_size, 1024);
        assert!(engine_config.rules.is_empty());
    }

    #[test]
    fn test_add_rule_new() {
        let mut config = EngineConfig::default();

        let rule = FilterRule {
            id: "rule-1".to_owned(),
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50))),
            dst_ip: None,
            dst_port: None,
            protocol: None,
            action: RuleAction::Block,
            description: "Block scanner".to_owned(),
        };

        config.add_rule(rule);

        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].id, "rule-1");
    }

    #[test]
    fn test_add_rule_replaces_existing() {
        let mut config = EngineConfig::default();

        let rule1 = FilterRule {
            id: "rule-1".to_owned(),
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50))),
            dst_ip: None,
            dst_port: None,
            protocol: None,
            action: RuleAction::Block,
            description: "First version".to_owned(),
        };

        let rule2 = FilterRule {
            id: "rule-1".to_owned(),
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 51))),
            dst_ip: None,
            dst_port: Some(443),
            protocol: Some(6),
            action: RuleAction::Monitor,
            description: "Second version".to_owned(),
        };

        config.add_rule(rule1);
        config.add_rule(rule2);

        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].description, "Second version");
        assert_eq!(config.rules[0].action, RuleAction::Monitor);
        assert_eq!(config.rules[0].dst_port, Some(443));
    }

    #[test]
    fn test_remove_rule_existing() {
        let mut config = EngineConfig::default();

        let rule = FilterRule {
            id: "rule-1".to_owned(),
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50))),
            dst_ip: None,
            dst_port: None,
            protocol: None,
            action: RuleAction::Block,
            description: "Test".to_owned(),
        };

        config.add_rule(rule);
        assert_eq!(config.rules.len(), 1);

        let removed = config.remove_rule("rule-1");
        assert!(removed);
        assert!(config.rules.is_empty());
    }

    #[test]
    fn test_remove_rule_nonexistent() {
        let mut config = EngineConfig::default();

        let removed = config.remove_rule("nonexistent");
        assert!(!removed);
    }

    #[test]
    fn test_remove_rule_preserves_others() {
        let mut config = EngineConfig::default();

        let rule1 = FilterRule {
            id: "rule-1".to_owned(),
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50))),
            dst_ip: None,
            dst_port: None,
            protocol: None,
            action: RuleAction::Block,
            description: "Rule 1".to_owned(),
        };

        let rule2 = FilterRule {
            id: "rule-2".to_owned(),
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 51))),
            dst_ip: None,
            dst_port: None,
            protocol: None,
            action: RuleAction::Monitor,
            description: "Rule 2".to_owned(),
        };

        config.add_rule(rule1);
        config.add_rule(rule2);

        let removed = config.remove_rule("rule-1");
        assert!(removed);
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].id, "rule-2");
    }

    #[test]
    fn test_ip_rules_filters_only_with_src_ip() {
        let mut config = EngineConfig::default();

        let rule_with_ip = FilterRule {
            id: "rule-with-ip".to_owned(),
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50))),
            dst_ip: None,
            dst_port: None,
            protocol: None,
            action: RuleAction::Block,
            description: "Has src_ip".to_owned(),
        };

        let rule_without_ip = FilterRule {
            id: "rule-without-ip".to_owned(),
            src_ip: None,
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            dst_port: Some(443),
            protocol: Some(6),
            action: RuleAction::Monitor,
            description: "No src_ip".to_owned(),
        };

        config.add_rule(rule_with_ip);
        config.add_rule(rule_without_ip);

        let ip_rules: Vec<_> = config.ip_rules().collect();
        assert_eq!(ip_rules.len(), 1);
        assert_eq!(ip_rules[0].id, "rule-with-ip");
    }

    #[test]
    fn test_ip_rules_empty_when_no_src_ip() {
        let mut config = EngineConfig::default();

        let rule = FilterRule {
            id: "no-ip".to_owned(),
            src_ip: None,
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            dst_port: Some(80),
            protocol: Some(6),
            action: RuleAction::Block,
            description: "No src_ip".to_owned(),
        };

        config.add_rule(rule);

        let ip_rules: Vec<_> = config.ip_rules().collect();
        assert!(ip_rules.is_empty());
    }

    // =============================================================================
    // load_rules 테스트
    // =============================================================================

    #[tokio::test]
    async fn test_load_rules_valid_toml() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let rules_path = tmp_dir.path().join("rules.toml");

        let toml_content = r#"
[[rules]]
id = "block-scanner"
src_ip = "10.0.0.50"
action = "block"
description = "Known port scanner"

[[rules]]
id = "monitor-suspicious"
src_ip = "192.168.1.100"
dst_port = 443
protocol = 6
action = "monitor"
description = "Suspicious internal host"
"#;

        tokio::fs::write(&rules_path, toml_content).await.unwrap();

        let rules = EngineConfig::load_rules(&rules_path).await.unwrap();

        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, "block-scanner");
        assert_eq!(rules[0].action, RuleAction::Block);
        assert_eq!(
            rules[0].src_ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)))
        );

        assert_eq!(rules[1].id, "monitor-suspicious");
        assert_eq!(rules[1].action, RuleAction::Monitor);
        assert_eq!(rules[1].dst_port, Some(443));
        assert_eq!(rules[1].protocol, Some(6));
    }

    #[tokio::test]
    async fn test_load_rules_empty_file() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let rules_path = tmp_dir.path().join("empty.toml");

        tokio::fs::write(&rules_path, "").await.unwrap();

        let rules = EngineConfig::load_rules(&rules_path).await.unwrap();
        assert!(rules.is_empty());
    }

    #[tokio::test]
    async fn test_load_rules_file_not_found() {
        let rules_path = "/nonexistent/path/rules.toml";

        let rules = EngineConfig::load_rules(rules_path).await.unwrap();
        assert!(rules.is_empty());
    }

    #[tokio::test]
    async fn test_load_rules_invalid_toml() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let rules_path = tmp_dir.path().join("invalid.toml");

        let invalid_toml = r#"
[[rules]]
id = "broken"
this is not valid toml
"#;

        tokio::fs::write(&rules_path, invalid_toml).await.unwrap();

        let result = EngineConfig::load_rules(&rules_path).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.to_string().contains("failed to parse rules file"));
    }

    #[tokio::test]
    async fn test_load_rules_invalid_ip() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let rules_path = tmp_dir.path().join("bad_ip.toml");

        let bad_ip_toml = r#"
[[rules]]
id = "bad-ip"
src_ip = "not.an.ip.address"
action = "block"
description = "Invalid IP"
"#;

        tokio::fs::write(&rules_path, bad_ip_toml).await.unwrap();

        let result = EngineConfig::load_rules(&rules_path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_load_rules_missing_required_fields() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let rules_path = tmp_dir.path().join("missing_fields.toml");

        let missing_toml = r#"
[[rules]]
src_ip = "10.0.0.1"
action = "block"
"#;

        tokio::fs::write(&rules_path, missing_toml).await.unwrap();

        let result = EngineConfig::load_rules(&rules_path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_load_rules_unicode_description() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let rules_path = tmp_dir.path().join("unicode.toml");

        let unicode_toml = r#"
[[rules]]
id = "unicode-rule"
src_ip = "10.0.0.1"
action = "block"
description = "한글 설명 및 이모지 🚨"
"#;

        tokio::fs::write(&rules_path, unicode_toml).await.unwrap();

        let rules = EngineConfig::load_rules(&rules_path).await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].description, "한글 설명 및 이모지 🚨");
    }

    #[tokio::test]
    async fn test_load_rules_boundary_values() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let rules_path = tmp_dir.path().join("boundary.toml");

        let boundary_toml = r#"
[[rules]]
id = "boundary"
src_ip = "0.0.0.0"
dst_port = 1
protocol = 0
action = "monitor"
description = "Boundary values"

[[rules]]
id = "max-values"
src_ip = "255.255.255.255"
dst_port = 65535
protocol = 255
action = "block"
description = "Max values"
"#;

        tokio::fs::write(&rules_path, boundary_toml).await.unwrap();

        let rules = EngineConfig::load_rules(&rules_path).await.unwrap();
        assert_eq!(rules.len(), 2);

        assert_eq!(rules[0].src_ip, Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        assert_eq!(rules[0].dst_port, Some(1));
        assert_eq!(rules[0].protocol, Some(0));

        assert_eq!(
            rules[1].src_ip,
            Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)))
        );
        assert_eq!(rules[1].dst_port, Some(65535));
        assert_eq!(rules[1].protocol, Some(255));
    }
}
