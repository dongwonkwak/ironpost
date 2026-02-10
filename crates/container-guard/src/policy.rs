//! 격리 정책 -- 컨테이너 보안 정책 정의 및 평가
//!
//! [`SecurityPolicy`]는 어떤 알림에 대해 어떤 격리 액션을 수행할지 정의합니다.
//! [`PolicyEngine`]은 여러 정책을 관리하고, 알림에 대해 매칭되는 정책을 평가합니다.

use serde::{Deserialize, Serialize};

use ironpost_core::event::AlertEvent;
use ironpost_core::types::{ContainerInfo, Severity};

use crate::error::ContainerGuardError;
use crate::isolation::IsolationAction;

/// Maximum policy file size (10 MB) to prevent OOM via malicious TOML
const MAX_POLICY_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum number of policies to prevent unbounded Vec growth
const MAX_POLICIES: usize = 1000;

/// 대상 컨테이너 필터
///
/// 정책이 적용되는 컨테이너 범위를 지정합니다.
/// 비어있는 필터는 모든 컨테이너에 매칭됩니다.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetFilter {
    /// 컨테이너 이름 패턴 (glob 스타일, 예: "web-*")
    /// 비어있으면 모든 컨테이너에 매칭
    #[serde(default)]
    pub container_names: Vec<String>,
    /// 이미지 이름 패턴 (glob 스타일, 예: "nginx:*")
    /// 비어있으면 모든 이미지에 매칭
    #[serde(default)]
    pub image_patterns: Vec<String>,
    /// 라벨 셀렉터 (key=value 형식)
    /// 비어있으면 모든 컨테이너에 매칭
    #[serde(default)]
    pub labels: Vec<String>,
}

impl TargetFilter {
    /// 컨테이너가 이 필터에 매칭되는지 확인합니다.
    ///
    /// 필터가 비어있으면 모든 컨테이너에 매칭됩니다.
    /// 여러 필터가 설정되면 모두 만족해야 합니다(AND 조건).
    pub fn matches(&self, container: &ContainerInfo) -> bool {
        let name_matches = self.container_names.is_empty()
            || self
                .container_names
                .iter()
                .any(|pattern| glob_match(pattern, &container.name));

        let image_matches = self.image_patterns.is_empty()
            || self
                .image_patterns
                .iter()
                .any(|pattern| glob_match(pattern, &container.image));

        name_matches && image_matches
    }
}

/// 간단한 glob 패턴 매칭 (*, ? 지원)
///
/// 전체 정규식 대신 단순 glob 패턴만 지원합니다.
/// - `*`: 0개 이상의 임의 문자
/// - `?`: 정확히 1개의 임의 문자
fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let mut pattern_chars = pattern.chars().peekable();
    let mut text_chars = text.chars().peekable();

    // Simple glob matching without recursion for safety
    let mut p_idx = 0;
    let mut t_idx = 0;
    let mut star_p_idx: Option<usize> = None;
    let mut star_t_idx: usize = 0;

    let pattern_bytes: Vec<char> = pattern_chars.by_ref().collect();
    let text_bytes: Vec<char> = text_chars.by_ref().collect();

    while t_idx < text_bytes.len() {
        if p_idx < pattern_bytes.len()
            && (pattern_bytes[p_idx] == '?' || pattern_bytes[p_idx] == text_bytes[t_idx])
        {
            p_idx += 1;
            t_idx += 1;
        } else if p_idx < pattern_bytes.len() && pattern_bytes[p_idx] == '*' {
            star_p_idx = Some(p_idx);
            star_t_idx = t_idx;
            p_idx += 1;
        } else if let Some(sp) = star_p_idx {
            p_idx = sp + 1;
            star_t_idx += 1;
            t_idx = star_t_idx;
        } else {
            return false;
        }
    }

    while p_idx < pattern_bytes.len() && pattern_bytes[p_idx] == '*' {
        p_idx += 1;
    }

    p_idx == pattern_bytes.len()
}

/// 보안 정책
///
/// 특정 심각도 이상의 알림에 대해 어떤 격리 액션을 수행할지 정의합니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// 정책 고유 ID
    pub id: String,
    /// 정책 이름
    pub name: String,
    /// 정책 설명
    pub description: String,
    /// 활성화 여부
    pub enabled: bool,
    /// 이 정책이 트리거되는 최소 심각도
    pub severity_threshold: Severity,
    /// 대상 컨테이너 필터
    pub target_filter: TargetFilter,
    /// 실행할 격리 액션
    pub action: IsolationAction,
    /// 정책 우선순위 (낮을수록 먼저 평가)
    pub priority: u32,
}

impl SecurityPolicy {
    /// 정책의 유효성을 검증합니다.
    pub fn validate(&self) -> Result<(), ContainerGuardError> {
        if self.id.is_empty() {
            return Err(ContainerGuardError::PolicyValidation {
                policy_id: "(empty)".to_owned(),
                reason: "policy id cannot be empty".to_owned(),
            });
        }

        if self.name.is_empty() {
            return Err(ContainerGuardError::PolicyValidation {
                policy_id: self.id.clone(),
                reason: "policy name cannot be empty".to_owned(),
            });
        }

        // Label-based filtering is not yet implemented in TargetFilter::matches().
        // Reject non-empty labels to prevent a false sense of security.
        if !self.target_filter.labels.is_empty() {
            return Err(ContainerGuardError::PolicyValidation {
                policy_id: self.id.clone(),
                reason:
                    "label-based filtering is not yet supported; remove labels from target_filter"
                        .to_owned(),
            });
        }

        Ok(())
    }

    /// 알림이 이 정책의 심각도 조건을 만족하는지 확인합니다.
    pub fn severity_matches(&self, alert: &AlertEvent) -> bool {
        alert.severity >= self.severity_threshold
    }
}

/// 정책 평가 결과
///
/// 어떤 정책이 매칭되었고 어떤 액션을 수행해야 하는지를 나타냅니다.
#[derive(Debug, Clone)]
pub struct PolicyMatch {
    /// 매칭된 정책 ID
    pub policy_id: String,
    /// 매칭된 정책 이름
    pub policy_name: String,
    /// 수행할 격리 액션
    pub action: IsolationAction,
}

/// 정책 엔진 -- 여러 정책을 관리하고 알림에 대해 평가합니다.
///
/// 정책은 우선순위 순으로 평가되며, 첫 번째로 매칭되는 정책의 액션이 반환됩니다.
pub struct PolicyEngine {
    /// 등록된 정책 목록 (우선순위 순으로 정렬)
    policies: Vec<SecurityPolicy>,
}

impl PolicyEngine {
    /// 빈 정책 엔진을 생성합니다.
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// 정책을 추가합니다.
    ///
    /// 추가 후 우선순위 순으로 자동 정렬됩니다.
    pub fn add_policy(&mut self, policy: SecurityPolicy) -> Result<(), ContainerGuardError> {
        if self.policies.len() >= MAX_POLICIES {
            return Err(ContainerGuardError::PolicyValidation {
                policy_id: policy.id.clone(),
                reason: format!("maximum policy count ({MAX_POLICIES}) reached"),
            });
        }

        policy.validate()?;
        self.policies.push(policy);
        self.policies.sort_by_key(|p| p.priority);
        Ok(())
    }

    /// 정책을 ID로 제거합니다.
    ///
    /// 존재하지 않는 ID를 지정하면 아무 일도 하지 않습니다.
    pub fn remove_policy(&mut self, policy_id: &str) {
        self.policies.retain(|p| p.id != policy_id);
    }

    /// 등록된 정책 수를 반환합니다.
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// 모든 정책을 제거합니다.
    pub fn clear(&mut self) {
        self.policies.clear();
    }

    /// 알림과 컨테이너 정보에 대해 정책을 평가합니다.
    ///
    /// 우선순위가 가장 높은(priority 값이 가장 낮은) 매칭 정책의 액션을 반환합니다.
    /// 매칭되는 정책이 없으면 `None`을 반환합니다.
    pub fn evaluate(&self, alert: &AlertEvent, container: &ContainerInfo) -> Option<PolicyMatch> {
        for policy in &self.policies {
            if !policy.enabled {
                continue;
            }

            if !policy.severity_matches(alert) {
                continue;
            }

            if !policy.target_filter.matches(container) {
                continue;
            }

            return Some(PolicyMatch {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                action: policy.action.clone(),
            });
        }

        None
    }

    /// 등록된 정책 목록을 반환합니다 (읽기 전용).
    pub fn policies(&self) -> &[SecurityPolicy] {
        &self.policies
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// TOML 파일에서 정책을 로드합니다.
///
/// # Arguments
/// - `path`: TOML 파일 경로
///
/// # Errors
/// - 파일 읽기 실패
/// - TOML 파싱 실패
/// - 정책 유효성 검증 실패
pub fn load_policy_from_file(
    path: &std::path::Path,
) -> Result<SecurityPolicy, ContainerGuardError> {
    // Check file size before reading to prevent OOM
    let metadata = std::fs::metadata(path).map_err(|e| ContainerGuardError::PolicyLoad {
        path: path.display().to_string(),
        reason: format!("failed to read metadata: {e}"),
    })?;

    if metadata.len() > MAX_POLICY_FILE_SIZE {
        return Err(ContainerGuardError::PolicyLoad {
            path: path.display().to_string(),
            reason: format!(
                "file too large: {} bytes (max: {MAX_POLICY_FILE_SIZE})",
                metadata.len()
            ),
        });
    }

    let content = std::fs::read_to_string(path).map_err(|e| ContainerGuardError::PolicyLoad {
        path: path.display().to_string(),
        reason: format!("failed to read file: {e}"),
    })?;

    let policy: SecurityPolicy =
        toml::from_str(&content).map_err(|e| ContainerGuardError::PolicyLoad {
            path: path.display().to_string(),
            reason: format!("failed to parse TOML: {e}"),
        })?;

    policy.validate()?;
    Ok(policy)
}

/// 디렉토리의 모든 TOML 파일에서 정책을 로드합니다.
///
/// # Arguments
/// - `dir_path`: 정책 파일 디렉토리 경로
///
/// # Returns
/// - 로드된 정책 목록 (파싱 실패한 파일은 스킵됨)
pub fn load_policies_from_dir(
    dir_path: &std::path::Path,
) -> Result<Vec<SecurityPolicy>, ContainerGuardError> {
    // Remove TOCTOU-vulnerable exists() checks - read_dir will fail if directory doesn't exist
    let mut policies = Vec::new();
    let entries = std::fs::read_dir(dir_path).map_err(|e| ContainerGuardError::PolicyLoad {
        path: dir_path.display().to_string(),
        reason: format!("failed to read directory: {e}"),
    })?;

    // Canonicalize the directory path ONCE before the loop to prevent TOCTOU races
    let canonical_dir = dir_path
        .canonicalize()
        .map_err(|e| ContainerGuardError::PolicyLoad {
            path: dir_path.display().to_string(),
            reason: format!("failed to canonicalize directory: {e}"),
        })?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "failed to read directory entry");
                continue;
            }
        };

        let path = entry.path();

        // Validate path to prevent symlink traversal attacks
        let canonical_path = match path.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "failed to canonicalize path, skipping");
                continue;
            }
        };

        // Verify canonical path is still within the policy directory
        if !canonical_path.starts_with(&canonical_dir) {
            tracing::warn!(
                path = %path.display(),
                canonical = %canonical_path.display(),
                "path traversal detected, skipping"
            );
            continue;
        }

        if !canonical_path.is_file() {
            continue;
        }

        if let Some(ext) = canonical_path.extension() {
            if ext != "toml" {
                continue;
            }
        } else {
            continue;
        }

        match load_policy_from_file(&canonical_path) {
            Ok(policy) => {
                tracing::debug!(policy_id = %policy.id, path = %canonical_path.display(), "loaded policy");
                policies.push(policy);
            }
            Err(e) => {
                tracing::warn!(path = %canonical_path.display(), error = %e, "failed to load policy file");
            }
        }
    }

    Ok(policies)
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use ironpost_core::types::Alert;

    use super::*;

    fn sample_alert_event(severity: Severity) -> AlertEvent {
        AlertEvent::new(
            Alert {
                id: "alert-001".to_owned(),
                title: "Test Alert".to_owned(),
                description: "test description".to_owned(),
                severity,
                rule_name: "test_rule".to_owned(),
                source_ip: None,
                target_ip: None,
                created_at: SystemTime::now(),
            },
            severity,
        )
    }

    fn sample_container(name: &str, image: &str) -> ContainerInfo {
        ContainerInfo {
            id: "abc123def456".to_owned(),
            name: name.to_owned(),
            image: image.to_owned(),
            status: "running".to_owned(),
            created_at: SystemTime::now(),
        }
    }

    fn sample_policy(severity: Severity, priority: u32) -> SecurityPolicy {
        SecurityPolicy {
            id: format!("policy-{priority}"),
            name: format!("Test Policy {priority}"),
            description: "Test policy".to_owned(),
            enabled: true,
            severity_threshold: severity,
            target_filter: TargetFilter::default(),
            action: IsolationAction::Pause,
            priority,
        }
    }

    #[test]
    fn glob_match_wildcard_all() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn glob_match_exact() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "world"));
    }

    #[test]
    fn glob_match_prefix_wildcard() {
        assert!(glob_match("web-*", "web-server"));
        assert!(glob_match("web-*", "web-"));
        assert!(!glob_match("web-*", "api-server"));
    }

    #[test]
    fn glob_match_suffix_wildcard() {
        assert!(glob_match("*:latest", "nginx:latest"));
        assert!(!glob_match("*:latest", "nginx:1.0"));
    }

    #[test]
    fn glob_match_question_mark() {
        assert!(glob_match("web-?", "web-1"));
        assert!(!glob_match("web-?", "web-12"));
    }

    #[test]
    fn target_filter_empty_matches_all() {
        let filter = TargetFilter::default();
        let container = sample_container("any-name", "any-image");
        assert!(filter.matches(&container));
    }

    #[test]
    fn target_filter_name_pattern() {
        let filter = TargetFilter {
            container_names: vec!["web-*".to_owned()],
            ..Default::default()
        };
        assert!(filter.matches(&sample_container("web-server", "nginx:latest")));
        assert!(!filter.matches(&sample_container("api-server", "nginx:latest")));
    }

    #[test]
    fn target_filter_image_pattern() {
        let filter = TargetFilter {
            image_patterns: vec!["nginx:*".to_owned()],
            ..Default::default()
        };
        assert!(filter.matches(&sample_container("web", "nginx:latest")));
        assert!(!filter.matches(&sample_container("web", "redis:7")));
    }

    #[test]
    fn target_filter_combined_and() {
        let filter = TargetFilter {
            container_names: vec!["web-*".to_owned()],
            image_patterns: vec!["nginx:*".to_owned()],
            ..Default::default()
        };
        // Both must match
        assert!(filter.matches(&sample_container("web-server", "nginx:latest")));
        assert!(!filter.matches(&sample_container("api-server", "nginx:latest")));
        assert!(!filter.matches(&sample_container("web-server", "redis:7")));
    }

    #[test]
    fn policy_validate_rejects_empty_id() {
        let mut policy = sample_policy(Severity::High, 1);
        policy.id = String::new();
        assert!(policy.validate().is_err());
    }

    #[test]
    fn policy_validate_rejects_empty_name() {
        let mut policy = sample_policy(Severity::High, 1);
        policy.name = String::new();
        assert!(policy.validate().is_err());
    }

    #[test]
    fn policy_severity_matches() {
        let policy = sample_policy(Severity::High, 1);
        assert!(policy.severity_matches(&sample_alert_event(Severity::Critical)));
        assert!(policy.severity_matches(&sample_alert_event(Severity::High)));
        assert!(!policy.severity_matches(&sample_alert_event(Severity::Medium)));
        assert!(!policy.severity_matches(&sample_alert_event(Severity::Low)));
    }

    #[test]
    fn policy_engine_add_and_count() {
        let mut engine = PolicyEngine::new();
        assert_eq!(engine.policy_count(), 0);

        engine.add_policy(sample_policy(Severity::High, 1)).unwrap();
        assert_eq!(engine.policy_count(), 1);

        engine
            .add_policy(sample_policy(Severity::Medium, 2))
            .unwrap();
        assert_eq!(engine.policy_count(), 2);
    }

    #[test]
    fn policy_engine_remove() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(sample_policy(Severity::High, 1)).unwrap();
        engine.remove_policy("policy-1");
        assert_eq!(engine.policy_count(), 0);
    }

    #[test]
    fn policy_engine_evaluate_matches() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(sample_policy(Severity::High, 1)).unwrap();

        let alert = sample_alert_event(Severity::Critical);
        let container = sample_container("web-server", "nginx:latest");

        let result = engine.evaluate(&alert, &container);
        assert!(result.is_some());
        assert_eq!(result.unwrap().policy_id, "policy-1");
    }

    #[test]
    fn policy_engine_evaluate_no_match_low_severity() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(sample_policy(Severity::High, 1)).unwrap();

        let alert = sample_alert_event(Severity::Low);
        let container = sample_container("web-server", "nginx:latest");

        let result = engine.evaluate(&alert, &container);
        assert!(result.is_none());
    }

    #[test]
    fn policy_engine_evaluate_skips_disabled() {
        let mut engine = PolicyEngine::new();
        let mut policy = sample_policy(Severity::Info, 1);
        policy.enabled = false;
        engine.add_policy(policy).unwrap();

        let alert = sample_alert_event(Severity::Critical);
        let container = sample_container("web-server", "nginx:latest");

        let result = engine.evaluate(&alert, &container);
        assert!(result.is_none());
    }

    #[test]
    fn policy_engine_evaluate_priority_order() {
        let mut engine = PolicyEngine::new();

        let mut policy_low = sample_policy(Severity::Medium, 10);
        policy_low.action = IsolationAction::Stop;

        let mut policy_high = sample_policy(Severity::Medium, 1);
        policy_high.action = IsolationAction::Pause;

        // Add in reverse order to verify sorting
        engine.add_policy(policy_low).unwrap();
        engine.add_policy(policy_high).unwrap();

        let alert = sample_alert_event(Severity::High);
        let container = sample_container("web-server", "nginx:latest");

        let result = engine.evaluate(&alert, &container);
        assert!(result.is_some());
        let matched = result.unwrap();
        // Should match priority=1 first (Pause)
        assert_eq!(matched.policy_id, "policy-1");
        assert!(matches!(matched.action, IsolationAction::Pause));
    }

    #[test]
    fn policy_engine_clear() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(sample_policy(Severity::High, 1)).unwrap();
        engine.clear();
        assert_eq!(engine.policy_count(), 0);
    }

    #[test]
    fn policy_engine_default() {
        let engine = PolicyEngine::default();
        assert_eq!(engine.policy_count(), 0);
    }

    #[test]
    fn policy_serialize_roundtrip() {
        let policy = sample_policy(Severity::High, 1);
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: SecurityPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy.id, deserialized.id);
        assert_eq!(policy.name, deserialized.name);
    }

    #[test]
    fn load_policy_from_toml_string() {
        let toml_content = r#"
id = "critical-isolate"
name = "Isolate Critical Alerts"
description = "Isolate containers on critical severity alerts"
enabled = true
severity_threshold = "Critical"
priority = 1

[target_filter]
container_names = ["web-*"]
image_patterns = ["nginx:*"]
labels = []

[action]
Pause = []
"#;
        let policy: SecurityPolicy = toml::from_str(toml_content).unwrap();
        assert_eq!(policy.id, "critical-isolate");
        assert_eq!(policy.name, "Isolate Critical Alerts");
        assert!(policy.enabled);
        assert_eq!(policy.severity_threshold, Severity::Critical);
        assert_eq!(policy.priority, 1);
        policy.validate().unwrap();
    }

    #[test]
    fn load_policy_from_file_success() {
        let temp_dir = std::env::temp_dir();
        let policy_file = temp_dir.join("test_policy.toml");

        let toml_content = r#"
id = "test-policy"
name = "Test Policy"
description = "Test"
enabled = true
severity_threshold = "High"
priority = 10

[target_filter]
container_names = []
image_patterns = []
labels = []

[action]
Stop = []
"#;
        std::fs::write(&policy_file, toml_content).unwrap();

        let policy = super::load_policy_from_file(&policy_file).unwrap();
        assert_eq!(policy.id, "test-policy");
        assert_eq!(policy.name, "Test Policy");

        // Clean up
        std::fs::remove_file(&policy_file).unwrap();
    }

    #[test]
    fn load_policy_from_file_not_found() {
        let result = super::load_policy_from_file(std::path::Path::new("/nonexistent/policy.toml"));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContainerGuardError::PolicyLoad { .. }
        ));
    }

    #[test]
    fn load_policies_from_dir_success() {
        let temp_dir = std::env::temp_dir().join("test_policies");
        std::fs::create_dir_all(&temp_dir).unwrap();

        // Create two policy files
        let policy1 = temp_dir.join("policy1.toml");
        std::fs::write(
            &policy1,
            r#"
id = "p1"
name = "Policy 1"
description = "Test"
enabled = true
severity_threshold = "High"
priority = 1

[target_filter]
container_names = []
image_patterns = []
labels = []

[action]
Pause = []
"#,
        )
        .unwrap();

        let policy2 = temp_dir.join("policy2.toml");
        std::fs::write(
            &policy2,
            r#"
id = "p2"
name = "Policy 2"
description = "Test"
enabled = true
severity_threshold = "Medium"
priority = 2

[target_filter]
container_names = []
image_patterns = []
labels = []

[action]
Stop = []
"#,
        )
        .unwrap();

        // Create a non-TOML file (should be skipped)
        std::fs::write(temp_dir.join("readme.txt"), "test").unwrap();

        let policies = super::load_policies_from_dir(&temp_dir).unwrap();
        assert_eq!(policies.len(), 2);

        // Clean up
        std::fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn load_policies_from_dir_not_exists() {
        let result = super::load_policies_from_dir(std::path::Path::new("/nonexistent_dir"));
        assert!(result.is_err());
    }

    #[test]
    fn load_policies_from_dir_not_directory() {
        let temp_file = std::env::temp_dir().join("not_a_dir.txt");
        std::fs::write(&temp_file, "test").unwrap();

        let result = super::load_policies_from_dir(&temp_file);
        assert!(result.is_err());

        // Clean up
        std::fs::remove_file(&temp_file).unwrap();
    }

    // --- Edge Case Tests ---

    #[test]
    fn glob_match_empty_pattern() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "text"));
    }

    #[test]
    fn glob_match_empty_text() {
        assert!(glob_match("*", ""));
        assert!(!glob_match("text", ""));
    }

    #[test]
    fn glob_match_multiple_wildcards() {
        assert!(glob_match("*-*-*", "web-app-server"));
        assert!(glob_match("a*b*c", "abc"));
        assert!(glob_match("a*b*c", "aXYZbXYZc"));
        assert!(!glob_match("a*b*c", "ab"));
    }

    #[test]
    fn glob_match_multiple_question_marks() {
        assert!(glob_match("???", "abc"));
        assert!(!glob_match("???", "ab"));
        assert!(!glob_match("???", "abcd"));
    }

    #[test]
    fn glob_match_mixed_wildcards() {
        assert!(glob_match("web-?*", "web-1-server"));
        assert!(glob_match("*-?", "server-1"));
        assert!(!glob_match("*-?", "server"));
    }

    #[test]
    fn glob_match_unicode() {
        assert!(glob_match("*", "你好世界"));
        assert!(glob_match("你好*", "你好世界"));
        assert!(glob_match("*世界", "你好世界"));
    }

    #[test]
    fn glob_match_special_chars() {
        assert!(glob_match("file.txt", "file.txt"));
        assert!(glob_match("*.txt", "file.txt"));
        assert!(glob_match("file[1]", "file[1]")); // Literal brackets
    }

    #[test]
    fn target_filter_multiple_name_patterns_or_logic() {
        let filter = TargetFilter {
            container_names: vec!["web-*".to_owned(), "api-*".to_owned()],
            ..Default::default()
        };
        assert!(filter.matches(&sample_container("web-server", "nginx:latest")));
        assert!(filter.matches(&sample_container("api-gateway", "nginx:latest")));
        assert!(!filter.matches(&sample_container("db-postgres", "postgres:14")));
    }

    #[test]
    fn target_filter_multiple_image_patterns_or_logic() {
        let filter = TargetFilter {
            image_patterns: vec!["nginx:*".to_owned(), "redis:*".to_owned()],
            ..Default::default()
        };
        assert!(filter.matches(&sample_container("web", "nginx:latest")));
        assert!(filter.matches(&sample_container("cache", "redis:7")));
        assert!(!filter.matches(&sample_container("db", "postgres:14")));
    }

    #[test]
    fn policy_validate_accepts_valid_policy() {
        let policy = sample_policy(Severity::High, 1);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn policy_severity_matches_boundary() {
        let policy = sample_policy(Severity::Medium, 1);
        assert!(policy.severity_matches(&sample_alert_event(Severity::Medium)));
        assert!(policy.severity_matches(&sample_alert_event(Severity::High)));
        assert!(policy.severity_matches(&sample_alert_event(Severity::Critical)));
        assert!(!policy.severity_matches(&sample_alert_event(Severity::Low)));
        assert!(!policy.severity_matches(&sample_alert_event(Severity::Info)));
    }

    #[test]
    fn policy_engine_add_invalid_policy() {
        let mut engine = PolicyEngine::new();
        let mut policy = sample_policy(Severity::High, 1);
        policy.id = String::new(); // Invalid

        let result = engine.add_policy(policy);
        assert!(result.is_err());
        assert_eq!(engine.policy_count(), 0);
    }

    #[test]
    fn policy_engine_remove_nonexistent() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(sample_policy(Severity::High, 1)).unwrap();
        engine.remove_policy("nonexistent-policy-id");
        // Should not panic, policy count remains 1
        assert_eq!(engine.policy_count(), 1);
    }

    #[test]
    fn policy_engine_evaluate_with_no_policies() {
        let engine = PolicyEngine::new();
        let alert = sample_alert_event(Severity::Critical);
        let container = sample_container("web-server", "nginx:latest");

        let result = engine.evaluate(&alert, &container);
        assert!(result.is_none());
    }

    #[test]
    fn policy_engine_multiple_matching_returns_first() {
        let mut engine = PolicyEngine::new();

        let mut policy1 = sample_policy(Severity::Medium, 1);
        policy1.action = IsolationAction::Pause;

        let mut policy2 = sample_policy(Severity::Medium, 2);
        policy2.action = IsolationAction::Stop;

        engine.add_policy(policy1).unwrap();
        engine.add_policy(policy2).unwrap();

        let alert = sample_alert_event(Severity::High);
        let container = sample_container("web-server", "nginx:latest");

        let result = engine.evaluate(&alert, &container).unwrap();
        // Should match priority=1 first
        assert!(matches!(result.action, IsolationAction::Pause));
    }

    #[test]
    fn load_policy_from_file_invalid_toml() {
        let temp_file = std::env::temp_dir().join("invalid_policy.toml");
        std::fs::write(&temp_file, "this is not valid TOML {{{").unwrap();

        let result = super::load_policy_from_file(&temp_file);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContainerGuardError::PolicyLoad { .. }
        ));

        std::fs::remove_file(&temp_file).unwrap();
    }

    #[test]
    fn load_policy_from_file_missing_required_fields() {
        let temp_file = std::env::temp_dir().join("incomplete_policy.toml");
        let toml_content = r#"
id = "test"
# Missing name, enabled, etc
"#;
        std::fs::write(&temp_file, toml_content).unwrap();

        let result = super::load_policy_from_file(&temp_file);
        assert!(result.is_err());

        std::fs::remove_file(&temp_file).unwrap();
    }

    #[test]
    fn load_policies_from_dir_empty_directory() {
        let temp_dir = std::env::temp_dir().join("empty_policies");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let policies = super::load_policies_from_dir(&temp_dir).unwrap();
        assert_eq!(policies.len(), 0);

        std::fs::remove_dir(&temp_dir).unwrap();
    }

    #[test]
    fn load_policies_from_dir_mixed_valid_invalid() {
        let temp_dir = std::env::temp_dir().join("mixed_policies");
        std::fs::create_dir_all(&temp_dir).unwrap();

        // Valid policy
        std::fs::write(
            temp_dir.join("valid.toml"),
            r#"
id = "valid-policy"
name = "Valid"
description = "Test"
enabled = true
severity_threshold = "High"
priority = 1

[target_filter]
container_names = []
image_patterns = []
labels = []

[action]
Pause = []
"#,
        )
        .unwrap();

        // Invalid policy
        std::fs::write(temp_dir.join("invalid.toml"), "invalid toml {{{").unwrap();

        let policies = super::load_policies_from_dir(&temp_dir).unwrap();
        // Should load only the valid one
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].id, "valid-policy");

        std::fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn load_policies_from_dir_with_subdirectories() {
        let temp_dir = std::env::temp_dir().join("policies_with_subdirs");
        std::fs::create_dir_all(&temp_dir).unwrap();
        std::fs::create_dir_all(temp_dir.join("subdir")).unwrap();

        // Policy in main dir
        std::fs::write(
            temp_dir.join("main.toml"),
            r#"
id = "main-policy"
name = "Main"
description = "Test"
enabled = true
severity_threshold = "High"
priority = 1

[target_filter]
container_names = []
image_patterns = []
labels = []

[action]
Stop = []
"#,
        )
        .unwrap();

        // Policy in subdir (should be skipped by current impl)
        std::fs::write(
            temp_dir.join("subdir/sub.toml"),
            r#"
id = "sub-policy"
name = "Sub"
description = "Test"
enabled = true
severity_threshold = "High"
priority = 1

[target_filter]
container_names = []
image_patterns = []
labels = []

[action]
Pause = []
"#,
        )
        .unwrap();

        let policies = super::load_policies_from_dir(&temp_dir).unwrap();
        // Should only load main.toml (subdirs are skipped with is_file() check)
        assert_eq!(policies.len(), 1);

        std::fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn policy_serialize_all_action_types() {
        let actions = vec![
            IsolationAction::Pause,
            IsolationAction::Stop,
            IsolationAction::NetworkDisconnect {
                networks: vec!["bridge".to_owned()],
            },
        ];

        for action in actions {
            let policy = SecurityPolicy {
                id: "test".to_owned(),
                name: "Test".to_owned(),
                description: "Test".to_owned(),
                enabled: true,
                severity_threshold: Severity::High,
                target_filter: TargetFilter::default(),
                action: action.clone(),
                priority: 1,
            };

            let json = serde_json::to_string(&policy).unwrap();
            let deserialized: SecurityPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(policy.id, deserialized.id);
        }
    }

    // --- Additional Edge Case Tests ---

    /// Test policy with all severity levels
    #[test]
    fn policy_all_severity_levels() {
        let severities = vec![
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];

        for severity in severities {
            let policy = SecurityPolicy {
                id: "test".to_owned(),
                name: "Test".to_owned(),
                description: "Test".to_owned(),
                enabled: true,
                severity_threshold: severity,
                target_filter: TargetFilter::default(),
                action: IsolationAction::Pause,
                priority: 1,
            };

            assert!(policy.validate().is_ok());

            // Test that higher severities match
            if severity < Severity::Critical {
                let alert = sample_alert_event(Severity::Critical);
                assert!(policy.severity_matches(&alert));
            }
        }
    }

    /// Test that non-empty labels are rejected by validate() since matching is not implemented
    #[test]
    fn policy_validate_rejects_nonempty_labels() {
        let policy = SecurityPolicy {
            id: "label-policy".to_owned(),
            name: "Label Policy".to_owned(),
            description: "Test".to_owned(),
            enabled: true,
            severity_threshold: Severity::High,
            target_filter: TargetFilter {
                container_names: vec![],
                image_patterns: vec![],
                labels: vec!["env=prod".to_owned()],
            },
            action: IsolationAction::Pause,
            priority: 1,
        };

        let result = policy.validate();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("label-based filtering is not yet supported"));
    }

    /// Test Policy TOML with NetworkDisconnect action type parsing
    #[test]
    fn load_policy_network_disconnect_action_from_toml() {
        let toml_content = r#"
id = "net-isolate"
name = "Network Isolation"
description = "Disconnect containers from network"
enabled = true
severity_threshold = "High"
priority = 1

[target_filter]
container_names = ["web-*"]
image_patterns = []
labels = []

[action.NetworkDisconnect]
networks = ["bridge", "custom"]
"#;
        let policy: SecurityPolicy = toml::from_str(toml_content).unwrap();
        assert_eq!(policy.id, "net-isolate");
        assert!(matches!(
            policy.action,
            IsolationAction::NetworkDisconnect { .. }
        ));
        if let IsolationAction::NetworkDisconnect { networks } = &policy.action {
            assert_eq!(networks.len(), 2);
            assert_eq!(networks[0], "bridge");
            assert_eq!(networks[1], "custom");
        }
    }

    /// Test load_policies_from_dir with only non-TOML files
    #[test]
    fn load_policies_from_dir_only_non_toml_files() {
        let temp_dir = std::env::temp_dir().join("non_toml_policies");
        std::fs::create_dir_all(&temp_dir).unwrap();

        // Create only non-TOML files
        std::fs::write(temp_dir.join("readme.txt"), "test").unwrap();
        std::fs::write(temp_dir.join("config.json"), "{}").unwrap();
        std::fs::write(temp_dir.join("script.sh"), "#!/bin/bash").unwrap();

        let policies = super::load_policies_from_dir(&temp_dir).unwrap();
        // Should load no policies
        assert_eq!(policies.len(), 0);

        std::fs::remove_dir_all(&temp_dir).unwrap();
    }

    /// Test concurrent PolicyEngine evaluate calls
    #[test]
    fn policy_engine_concurrent_evaluate() {
        use std::sync::Arc;
        use std::thread;

        let mut engine = PolicyEngine::new();
        engine
            .add_policy(sample_policy(Severity::Medium, 1))
            .unwrap();
        engine.add_policy(sample_policy(Severity::High, 2)).unwrap();

        let engine = Arc::new(engine);
        let alert = Arc::new(sample_alert_event(Severity::High));
        let container = Arc::new(sample_container("web-server", "nginx:latest"));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let eng = Arc::clone(&engine);
                let alrt = Arc::clone(&alert);
                let cont = Arc::clone(&container);
                thread::spawn(move || eng.evaluate(&alrt, &cont))
            })
            .collect();

        // All should succeed and return consistent results
        for handle in handles {
            let result = handle.join().unwrap();
            assert!(result.is_some());
            let matched = result.unwrap();
            // Should match priority=1 first
            assert_eq!(matched.policy_id, "policy-1");
        }
    }
}
