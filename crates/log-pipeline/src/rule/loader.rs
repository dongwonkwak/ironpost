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

    #[tokio::test]
    async fn load_example_rules_directory() {
        // examples/rules/ 디렉토리에서 실제 규칙 로드
        let rules_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/rules");

        let rules = RuleLoader::load_directory(rules_path).await;

        // 디렉토리가 존재하면 규칙 로드 성공 확인
        if let Ok(rules) = rules {
            assert!(!rules.is_empty(), "should load at least one rule");

            // 모든 규칙이 유효한 ID를 가지는지 확인
            for rule in &rules {
                assert!(!rule.id.is_empty(), "rule id should not be empty");
                assert!(!rule.title.is_empty(), "rule title should not be empty");
            }

            tracing::info!("loaded {} example rules", rules.len());
        }
    }

    #[tokio::test]
    async fn load_specific_example_rules() {
        let base_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/rules");

        // SSH brute force 규칙 로드 테스트
        let ssh_rule_path = format!("{}/ssh_brute_force.yaml", base_path);
        if let Ok(rule) = RuleLoader::load_file(&ssh_rule_path).await {
            assert_eq!(rule.id, "ssh_brute_force");
            assert_eq!(rule.severity, Severity::High);
            assert!(rule.detection.threshold.is_some());
        }

        // Privilege escalation 규칙 로드 테스트
        let priv_rule_path = format!("{}/privilege_escalation.yaml", base_path);
        if let Ok(rule) = RuleLoader::load_file(&priv_rule_path).await {
            assert_eq!(rule.id, "privilege_escalation");
            assert_eq!(rule.severity, Severity::Critical);
        }
    }

    #[tokio::test]
    async fn duplicate_rule_ids_are_skipped() {
        use std::io::Write;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let rule_yaml = r#"
id: duplicate_test
title: Test Rule
severity: Low
detection:
  conditions:
    - field: test
      value: value
"#;

        // 동일한 ID를 가진 두 개의 파일 생성
        let file1_path = temp_dir.path().join("rule1.yaml");
        let file2_path = temp_dir.path().join("rule2.yaml");

        std::fs::File::create(&file1_path)
            .unwrap()
            .write_all(rule_yaml.as_bytes())
            .unwrap();
        std::fs::File::create(&file2_path)
            .unwrap()
            .write_all(rule_yaml.as_bytes())
            .unwrap();

        let rules = RuleLoader::load_directory(temp_dir.path()).await.unwrap();

        // 중복 ID는 스킵되므로 하나만 로드되어야 함
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "duplicate_test");
    }

    #[tokio::test]
    async fn mixed_valid_and_invalid_files() {
        use std::io::Write;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();

        // 유효한 규칙
        let valid_yaml = r#"
id: valid_rule
title: Valid Rule
severity: Medium
detection:
  conditions:
    - field: test
      value: value
"#;

        // 무효한 YAML
        let invalid_yaml = "not: [valid: yaml: {{{";

        let valid_path = temp_dir.path().join("valid.yaml");
        let invalid_path = temp_dir.path().join("invalid.yaml");
        let txt_path = temp_dir.path().join("not_yaml.txt");

        std::fs::File::create(&valid_path)
            .unwrap()
            .write_all(valid_yaml.as_bytes())
            .unwrap();
        std::fs::File::create(&invalid_path)
            .unwrap()
            .write_all(invalid_yaml.as_bytes())
            .unwrap();
        std::fs::File::create(&txt_path)
            .unwrap()
            .write_all(b"some text file")
            .unwrap();

        let rules = RuleLoader::load_directory(temp_dir.path()).await.unwrap();

        // 유효한 규칙만 로드되고, 무효한 YAML은 경고 후 스킵
        // .txt 파일은 무시됨
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "valid_rule");
    }

    #[tokio::test]
    async fn load_file_too_large_returns_error() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut temp_file = NamedTempFile::new().unwrap();

        // MAX_RULE_FILE_SIZE를 초과하는 파일 생성 (10MB + 1 byte)
        let large_content = vec![b'x'; (MAX_RULE_FILE_SIZE + 1) as usize];
        temp_file.write_all(&large_content).unwrap();

        let result = RuleLoader::load_file(temp_file.path()).await;
        assert!(result.is_err());

        if let Err(LogPipelineError::RuleLoad { reason, .. }) = result {
            assert!(reason.contains("file too large"));
        }
    }
}
