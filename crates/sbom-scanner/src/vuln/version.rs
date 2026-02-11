//! 시맨틱 버전 비교 -- SemVer 범위 매칭
//!
//! `semver` 크레이트를 사용하여 패키지 버전이 취약점 영향 범위에 포함되는지 확인합니다.
//! SemVer가 아닌 버전 문자열은 보수적으로 매칭하지 않습니다(오탐 방지).

use super::db::VersionRange;

/// 주어진 버전이 취약점 영향 범위에 포함되는지 확인합니다.
///
/// # 매칭 규칙
///
/// - `introduced`가 None이면 모든 버전이 영향받음 (시작 제한 없음)
/// - `fixed`가 None이면 아직 수정되지 않음 (모든 이후 버전이 영향)
/// - `introduced <= version < fixed`이면 영향받음
///
/// SemVer 파싱이 실패하면 보수적으로 매칭하지 않습니다(오탐 방지).
///
/// 여러 범위 중 하나라도 매칭되면 `true`를 반환합니다.
pub fn is_affected(version_str: &str, ranges: &[VersionRange]) -> bool {
    // 범위가 비어있으면 매칭하지 않음
    if ranges.is_empty() {
        return false;
    }

    for range in ranges {
        if is_in_range(version_str, range) {
            return true;
        }
    }

    false
}

/// 단일 버전 범위에 대해 매칭 여부를 확인합니다.
fn is_in_range(version_str: &str, range: &VersionRange) -> bool {
    // SemVer 파싱 시도
    if let Ok(version) = semver::Version::parse(version_str) {
        return is_in_range_semver(&version, range);
    }

    // leading 'v' 또는 'V' 제거 후 재시도 (흔한 비표준 접두사)
    if version_str.starts_with('v') || version_str.starts_with('V') {
        let normalized = &version_str[1..];
        if let Ok(version) = semver::Version::parse(normalized) {
            return is_in_range_semver(&version, range);
        }
    }

    // 비표준 버전 문자열: 보수적으로 매칭하지 않음
    // 보안 스캐닝에서 일반적으로 false positive(오탐)가 false negative(누락)보다
    // 선호되지만, 비-SemVer 문자열은 신뢰할 수 있는 비교가 불가능하므로
    // 오탐을 피하기 위해 매칭하지 않습니다 (단, 실제 취약점 누락 가능성 있음).
    tracing::warn!(
        version = %version_str,
        "non-SemVer version string encountered, conservatively not matching (may miss vulnerability)"
    );
    false
}

/// SemVer 버전으로 범위 매칭
fn is_in_range_semver(version: &semver::Version, range: &VersionRange) -> bool {
    // introduced 확인
    if let Some(ref introduced) = range.introduced {
        match semver::Version::parse(introduced) {
            Ok(intro_ver) => {
                if version < &intro_ver {
                    return false;
                }
            }
            Err(_) => {
                // SemVer 파싱 실패: 범위 무효로 간주하여 매칭 실패
                tracing::warn!(
                    introduced = %introduced,
                    "failed to parse introduced version as SemVer, range ignored"
                );
                return false;
            }
        }
    }

    // fixed 확인
    if let Some(ref fixed) = range.fixed {
        match semver::Version::parse(fixed) {
            Ok(fix_ver) => {
                if version >= &fix_ver {
                    return false;
                }
            }
            Err(_) => {
                // SemVer 파싱 실패: 범위 무효로 간주하여 매칭 실패
                tracing::warn!(
                    fixed = %fixed,
                    "failed to parse fixed version as SemVer, range ignored"
                );
                return false;
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn affected_in_range() {
        let ranges = vec![VersionRange {
            introduced: Some("1.0.0".to_owned()),
            fixed: Some("1.0.5".to_owned()),
        }];

        assert!(is_affected("1.0.0", &ranges));
        assert!(is_affected("1.0.3", &ranges));
        assert!(is_affected("1.0.4", &ranges));
    }

    #[test]
    fn not_affected_before_range() {
        let ranges = vec![VersionRange {
            introduced: Some("1.0.0".to_owned()),
            fixed: Some("1.0.5".to_owned()),
        }];

        assert!(!is_affected("0.9.0", &ranges));
    }

    #[test]
    fn not_affected_at_fixed_version() {
        let ranges = vec![VersionRange {
            introduced: Some("1.0.0".to_owned()),
            fixed: Some("1.0.5".to_owned()),
        }];

        assert!(!is_affected("1.0.5", &ranges));
        assert!(!is_affected("1.1.0", &ranges));
    }

    #[test]
    fn affected_no_fixed_version() {
        let ranges = vec![VersionRange {
            introduced: Some("1.0.0".to_owned()),
            fixed: None,
        }];

        assert!(is_affected("1.0.0", &ranges));
        assert!(is_affected("2.0.0", &ranges));
        assert!(is_affected("99.99.99", &ranges));
    }

    #[test]
    fn affected_no_introduced_version() {
        let ranges = vec![VersionRange {
            introduced: None,
            fixed: Some("1.0.5".to_owned()),
        }];

        assert!(is_affected("0.1.0", &ranges));
        assert!(is_affected("1.0.4", &ranges));
        assert!(!is_affected("1.0.5", &ranges));
    }

    #[test]
    fn affected_no_bounds() {
        let ranges = vec![VersionRange {
            introduced: None,
            fixed: None,
        }];

        // All versions affected
        assert!(is_affected("0.0.1", &ranges));
        assert!(is_affected("99.99.99", &ranges));
    }

    #[test]
    fn not_affected_empty_ranges() {
        assert!(!is_affected("1.0.0", &[]));
    }

    #[test]
    fn multiple_ranges_any_match() {
        let ranges = vec![
            VersionRange {
                introduced: Some("1.0.0".to_owned()),
                fixed: Some("1.0.5".to_owned()),
            },
            VersionRange {
                introduced: Some("2.0.0".to_owned()),
                fixed: Some("2.0.3".to_owned()),
            },
        ];

        assert!(is_affected("1.0.3", &ranges));
        assert!(is_affected("2.0.1", &ranges));
        assert!(!is_affected("1.5.0", &ranges));
    }

    #[test]
    fn non_semver_conservatively_not_matched() {
        let ranges = vec![VersionRange {
            introduced: Some("abc".to_owned()),
            fixed: Some("def".to_owned()),
        }];

        // 비 SemVer 문자열은 보수적으로 매칭하지 않음 (false positive 방지)
        assert!(!is_affected("bcd", &ranges));
        assert!(!is_affected("aaa", &ranges));
        assert!(!is_affected("xyz", &ranges));
    }

    #[test]
    fn semver_with_prerelease() {
        let ranges = vec![VersionRange {
            introduced: Some("1.0.0".to_owned()),
            fixed: Some("1.0.5".to_owned()),
        }];

        // Pre-release versions: 1.0.3-alpha < 1.0.3 in SemVer
        assert!(is_affected("1.0.3-alpha", &ranges));
    }

    // Additional edge case tests

    #[test]
    fn wildcard_version_string_comparison() {
        let ranges = vec![VersionRange {
            introduced: Some("*".to_owned()),
            fixed: None,
        }];
        // Wildcard는 유효한 SemVer가 아니므로 범위가 무효로 처리됨
        // (파싱 실패 시 매칭 실패 정책)
        assert!(!is_affected("1.0.0", &ranges));
        assert!(!is_affected("2.0.0", &ranges));
    }

    #[test]
    fn very_long_version_string() {
        let long_version = "1.0.0-".to_owned() + &"a".repeat(1000);
        let ranges = vec![VersionRange {
            introduced: Some("1.0.0".to_owned()),
            fixed: None,
        }];
        // Should handle very long version strings without panic
        // semver parsing fails, so falls back to string comparison
        // "1.0.0" <= "1.0.0-aaaa..." is false in string comparison
        // This is expected behavior for malformed semver
        let result = is_affected(&long_version, &ranges);
        // Just verify it doesn't panic - consume the value to avoid unused-value warnings
        let _ = result;
    }

    #[test]
    fn malformed_semver_conservatively_not_matched() {
        let ranges = vec![VersionRange {
            introduced: Some("not-a-semver".to_owned()),
            fixed: Some("zzz".to_owned()),
        }];
        // 비표준 버전은 보수적으로 매칭하지 않음
        assert!(!is_affected("some-version", &ranges));
        assert!(!is_affected("aaa", &ranges));
    }

    #[test]
    fn semver_with_build_metadata() {
        let ranges = vec![VersionRange {
            introduced: Some("1.0.0".to_owned()),
            fixed: Some("1.0.5".to_owned()),
        }];
        // Build metadata is ignored in SemVer comparison
        assert!(is_affected("1.0.3+20240101", &ranges));
    }

    #[test]
    fn semver_patch_version_boundary() {
        let ranges = vec![VersionRange {
            introduced: Some("1.0.0".to_owned()),
            fixed: Some("1.0.1".to_owned()),
        }];
        assert!(is_affected("1.0.0", &ranges));
        assert!(!is_affected("1.0.1", &ranges));
        assert!(!is_affected("1.0.2", &ranges));
    }

    #[test]
    fn semver_major_version_boundary() {
        let ranges = vec![VersionRange {
            introduced: Some("1.0.0".to_owned()),
            fixed: Some("2.0.0".to_owned()),
        }];
        assert!(is_affected("1.99.99", &ranges));
        assert!(!is_affected("2.0.0", &ranges));
        assert!(!is_affected("3.0.0", &ranges));
    }

    #[test]
    fn multiple_ranges_with_gaps() {
        let ranges = vec![
            VersionRange {
                introduced: Some("1.0.0".to_owned()),
                fixed: Some("1.1.0".to_owned()),
            },
            VersionRange {
                introduced: Some("2.0.0".to_owned()),
                fixed: Some("2.1.0".to_owned()),
            },
        ];
        assert!(is_affected("1.0.5", &ranges));
        assert!(!is_affected("1.5.0", &ranges)); // gap
        assert!(is_affected("2.0.5", &ranges));
    }

    #[test]
    fn empty_version_string() {
        let ranges = vec![VersionRange {
            introduced: Some("1.0.0".to_owned()),
            fixed: None,
        }];
        // Empty version should not match (falls back to string comparison)
        assert!(!is_affected("", &ranges));
    }

    #[test]
    fn unicode_version_string() {
        let ranges = vec![VersionRange {
            introduced: Some("1.0.0".to_owned()),
            fixed: Some("2.0.0".to_owned()),
        }];
        // Unicode 버전은 SemVer 파싱 실패 → 보수적으로 매칭하지 않음
        assert!(!is_affected("1.5.0-日本語", &ranges));
    }

    #[test]
    fn version_with_leading_v() {
        let ranges = vec![VersionRange {
            introduced: Some("1.0.0".to_owned()),
            fixed: Some("1.0.5".to_owned()),
        }];
        // leading 'v' 제거 후 "1.0.3"으로 파싱되어 정상 매칭
        let result = is_affected("v1.0.3", &ranges);
        assert!(result); // "v1.0.3" → "1.0.3" → 범위 [1.0.0, 1.0.5) 내에 있음
    }

    #[test]
    fn zero_version() {
        let ranges = vec![VersionRange {
            introduced: Some("0.0.0".to_owned()),
            fixed: Some("0.1.0".to_owned()),
        }];
        assert!(is_affected("0.0.1", &ranges));
        assert!(is_affected("0.0.99", &ranges));
        assert!(!is_affected("0.1.0", &ranges));
    }

    #[test]
    fn exact_match_single_version() {
        let ranges = vec![VersionRange {
            introduced: Some("1.0.0".to_owned()),
            fixed: Some("1.0.1".to_owned()),
        }];
        // Only 1.0.0 is affected
        assert!(is_affected("1.0.0", &ranges));
        assert!(!is_affected("1.0.1", &ranges));
        assert!(!is_affected("0.9.99", &ranges));
    }
}
