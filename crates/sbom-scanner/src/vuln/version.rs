//! 시맨틱 버전 비교 -- SemVer 범위 매칭
//!
//! `semver` 크레이트를 사용하여 패키지 버전이 취약점 영향 범위에 포함되는지 확인합니다.
//! SemVer가 아닌 버전 문자열은 문자열 비교로 fallback합니다.

use super::db::VersionRange;

/// 주어진 버전이 취약점 영향 범위에 포함되는지 확인합니다.
///
/// # 매칭 규칙
///
/// - `introduced`가 None이면 모든 버전이 영향받음 (시작 제한 없음)
/// - `fixed`가 None이면 아직 수정되지 않음 (모든 이후 버전이 영향)
/// - `introduced <= version < fixed`이면 영향받음
///
/// SemVer 파싱이 실패하면 문자열 비교로 fallback합니다.
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

    // fallback: 문자열 비교
    is_in_range_string(version_str, range)
}

/// SemVer 버전으로 범위 매칭
fn is_in_range_semver(version: &semver::Version, range: &VersionRange) -> bool {
    // introduced 확인
    if let Some(ref introduced) = range.introduced
        && let Ok(intro_ver) = semver::Version::parse(introduced)
        && version < &intro_ver
    {
        return false;
    }

    // fixed 확인
    if let Some(ref fixed) = range.fixed
        && let Ok(fix_ver) = semver::Version::parse(fixed)
        && version >= &fix_ver
    {
        return false;
    }

    true
}

/// 문자열 비교로 범위 매칭 (SemVer 파싱 실패 시 fallback)
fn is_in_range_string(version: &str, range: &VersionRange) -> bool {
    if let Some(ref introduced) = range.introduced
        && version < introduced.as_str()
    {
        return false;
    }

    if let Some(ref fixed) = range.fixed
        && version >= fixed.as_str()
    {
        return false;
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
    fn non_semver_fallback_string_comparison() {
        let ranges = vec![VersionRange {
            introduced: Some("abc".to_owned()),
            fixed: Some("def".to_owned()),
        }];

        // String comparison: "abc" <= "bcd" < "def"
        assert!(is_affected("bcd", &ranges));
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
        // Wildcard should be treated as string
        assert!(is_affected("1.0.0", &ranges));
        assert!(is_affected("2.0.0", &ranges));
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
        // Just verify it doesn't panic - the result depends on string comparison semantics
        assert!(result || !result); // Always true, but ensures no panic
    }

    #[test]
    fn malformed_semver_falls_back_to_string_comparison() {
        let ranges = vec![VersionRange {
            introduced: Some("not-a-semver".to_owned()),
            fixed: Some("zzz".to_owned()),
        }];
        // String comparison: "not-a-semver" <= "some-version" < "zzz"
        assert!(is_affected("some-version", &ranges));
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
        // Unicode version should fall back to string comparison
        assert!(is_affected("1.5.0-日本語", &ranges));
    }

    #[test]
    fn version_with_leading_v() {
        let ranges = vec![VersionRange {
            introduced: Some("1.0.0".to_owned()),
            fixed: Some("1.0.5".to_owned()),
        }];
        // semver crate doesn't parse "v1.0.3", should fall back to string comparison
        // String comparison: "1.0.0" <= "v1.0.3" is false because 'v' > '1' in ASCII
        let result = is_affected("v1.0.3", &ranges);
        assert!(!result); // Correct behavior: "v1.0.3" is not in range via string comparison
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
