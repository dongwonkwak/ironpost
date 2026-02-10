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
}
