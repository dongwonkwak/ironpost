//! 규칙 파일 로더 -- YAML 규칙 파일을 디스크에서 로드합니다.
//!
//! 규칙 디렉토리 내의 `.yml`/`.yaml` 파일을 스캔하고 파싱합니다.
//! 개별 파일 파싱 실패는 경고 로그를 남기고 건너뜁니다.

use std::collections::HashSet;
use std::path::Path;

use crate::error::LogPipelineError;

use super::types::DetectionRule;

/// 규칙 파일 로더 설정
const MAX_RULE_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10MB
const MAX_RULES_COUNT: usize = 10_000;

/// 규칙 파일 로더
pub struct RuleLoader;

impl RuleLoader {
    /// 디렉토리에서 모든 YAML 규칙 파일을 로드합니다.
    ///
    /// `.yml` 또는 `.yaml` 확장자를 가진 파일만 처리합니다.
    /// 개별 파일 로딩 실패는 경고 로그를 남기고 건너뜁니다.
    ///
    /// # Errors
    /// - 디렉토리를 읽을 수 없는 경우
    /// - 규칙 수가 `MAX_RULES_COUNT`를 초과하는 경우
    pub async fn load_directory(
        dir: impl AsRef<Path>,
    ) -> Result<Vec<DetectionRule>, LogPipelineError> {
        let dir = dir.as_ref();

        let mut entries =
            tokio::fs::read_dir(dir)
                .await
                .map_err(|e| LogPipelineError::RuleLoad {
                    path: dir.display().to_string(),
                    reason: format!("failed to read directory: {e}"),
                })?;

        let mut rules = Vec::new();
        let mut seen_ids = HashSet::new();

        while let Some(entry) =
            entries
                .next_entry()
                .await
                .map_err(|e| LogPipelineError::RuleLoad {
                    path: dir.display().to_string(),
                    reason: format!("failed to read directory entry: {e}"),
                })?
        {
            let path = entry.path();

            // .yml / .yaml 확장자만 처리
            let is_yaml = path
                .extension()
                .is_some_and(|ext| ext == "yml" || ext == "yaml");

            if !is_yaml {
                continue;
            }

            match Self::load_file(&path).await {
                Ok(rule) => {
                    // 중복 ID 검사
                    if seen_ids.contains(&rule.id) {
                        tracing::warn!(
                            rule_id = %rule.id,
                            path = %path.display(),
                            "duplicate rule id, skipping"
                        );
                        continue;
                    }
                    seen_ids.insert(rule.id.clone());
                    rules.push(rule);
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "failed to load rule file, skipping"
                    );
                }
            }

            if rules.len() > MAX_RULES_COUNT {
                return Err(LogPipelineError::RuleLoad {
                    path: dir.display().to_string(),
                    reason: format!("too many rules: max {MAX_RULES_COUNT}"),
                });
            }
        }

        tracing::info!(
            dir = %dir.display(),
            count = rules.len(),
            "loaded detection rules"
        );

        Ok(rules)
    }

    /// 단일 YAML 파일에서 규칙을 로드합니다.
    pub async fn load_file(path: impl AsRef<Path>) -> Result<DetectionRule, LogPipelineError> {
        let path = path.as_ref();

        // 파일 크기 검증
        let metadata = tokio::fs::metadata(path)
            .await
            .map_err(|e| LogPipelineError::RuleLoad {
                path: path.display().to_string(),
                reason: format!("failed to read file metadata: {e}"),
            })?;

        if metadata.len() > MAX_RULE_FILE_SIZE {
            return Err(LogPipelineError::RuleLoad {
                path: path.display().to_string(),
                reason: format!(
                    "file too large: {} bytes (max: {MAX_RULE_FILE_SIZE})",
                    metadata.len()
                ),
            });
        }

        let content =
            tokio::fs::read_to_string(path)
                .await
                .map_err(|e| LogPipelineError::RuleLoad {
                    path: path.display().to_string(),
                    reason: format!("failed to read file: {e}"),
                })?;

        Self::parse_yaml(&content, &path.display().to_string())
    }

    /// YAML 문자열을 파싱하여 규칙을 생성합니다.
    pub fn parse_yaml(yaml_str: &str, source: &str) -> Result<DetectionRule, LogPipelineError> {
        let rule: DetectionRule =
            serde_yaml::from_str(yaml_str).map_err(|e| LogPipelineError::RuleLoad {
                path: source.to_owned(),
                reason: format!("YAML parse error: {e}"),
            })?;

        // 유효성 검증
        rule.validate()?;

        Ok(rule)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironpost_core::types::Severity;

    #[test]
    fn parse_valid_yaml() {
        let yaml = r#"
id: test_rule
title: Test Rule
severity: Medium
detection:
  conditions:
    - field: process
      value: sshd
"#;
        let rule = RuleLoader::parse_yaml(yaml, "test.yml").unwrap();
        assert_eq!(rule.id, "test_rule");
        assert_eq!(rule.severity, Severity::Medium);
    }

    #[test]
    fn parse_invalid_yaml_returns_error() {
        let yaml = "not: [valid: yaml: {{{";
        let result = RuleLoader::parse_yaml(yaml, "bad.yml");
        assert!(result.is_err());
    }

    #[test]
    fn parse_yaml_with_missing_required_fields() {
        let yaml = r#"
id: ""
title: ""
severity: Medium
detection:
  conditions: []
"#;
        let result = RuleLoader::parse_yaml(yaml, "empty_id.yml");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn load_nonexistent_directory_returns_error() {
        let result = RuleLoader::load_directory("/nonexistent/path/rules").await;
        assert!(result.is_err());
    }
}
