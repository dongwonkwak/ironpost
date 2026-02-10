//! SBOM 생성 유틸리티 -- 공유 헬퍼 함수

use crate::types::Ecosystem;

/// NPM integrity 필드나 Cargo checksum에서 알고리즘과 해시 값을 추출합니다.
///
/// # Arguments
///
/// - `checksum`: 원본 체크섬 문자열 (예: "sha512-abc123..." 또는 "abc123...")
/// - `ecosystem`: 패키지 생태계
///
/// # Returns
///
/// `(알고리즘명, 해시값)` 튜플. NPM의 경우 "sha512-" 접두사를 파싱하고,
/// Cargo/Go/Pip의 경우 "SHA-256"을 기본값으로 사용합니다.
pub fn parse_checksum_algorithm<'a>(
    checksum: &'a str,
    ecosystem: &Ecosystem,
) -> (&'static str, &'a str) {
    match ecosystem {
        Ecosystem::Npm => {
            // NPM integrity: "sha512-base64hash" 형식
            if let Some(dash_idx) = checksum.find('-') {
                let (alg_part, hash_part) = checksum.split_at(dash_idx);
                let hash_value = &hash_part[1..]; // skip '-'
                let algorithm = match alg_part {
                    "sha512" => "SHA-512",
                    "sha384" => "SHA-384",
                    "sha256" => "SHA-256",
                    "sha1" => "SHA-1",
                    _ => "SHA-256",
                };
                (algorithm, hash_value)
            } else {
                ("SHA-256", checksum)
            }
        }
        _ => ("SHA-256", checksum), // Cargo, Go, Pip 등은 SHA-256 사용
    }
}

/// 현재 Unix 타임스탬프를 RFC3339 형식으로 반환합니다.
///
/// 시스템 시간을 가져올 수 없는 경우 epoch(1970-01-01T00:00:00Z)를 반환합니다.
pub fn current_timestamp() -> String {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            unix_to_rfc3339(secs)
        }
        Err(_) => "1970-01-01T00:00:00Z".to_owned(),
    }
}

/// Unix timestamp를 RFC3339 형식 (YYYY-MM-DDTHH:MM:SSZ)으로 변환합니다.
pub fn unix_to_rfc3339(secs: u64) -> String {
    const SECONDS_PER_DAY: u64 = 86400;
    const SECONDS_PER_HOUR: u64 = 3600;
    const SECONDS_PER_MINUTE: u64 = 60;

    // Unix epoch (1970-01-01) 이후의 일수 계산
    let days_since_epoch = secs / SECONDS_PER_DAY;
    let remaining_secs = secs % SECONDS_PER_DAY;

    let hours = remaining_secs / SECONDS_PER_HOUR;
    let minutes = (remaining_secs % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE;
    let seconds = remaining_secs % SECONDS_PER_MINUTE;

    // 그레고리안 달력 계산 (간소화된 버전)
    let mut year = 1970;
    let mut days = days_since_epoch;

    // 연도 계산
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days >= days_in_year {
            days -= days_in_year;
            year += 1;
        } else {
            break;
        }
    }

    // 월과 일 계산
    let days_in_months: [u64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    let mut day = days + 1;

    for &days_in_month in &days_in_months {
        if day <= days_in_month {
            break;
        }
        day -= days_in_month;
        month += 1;
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// 윤년 판별
fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unix_to_rfc3339_epoch() {
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_unix_to_rfc3339_known_date() {
        // 2024-01-01T00:00:00Z = 1704067200 seconds
        assert_eq!(unix_to_rfc3339(1704067200), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn test_is_leap_year() {
        assert!(is_leap_year(2000)); // divisible by 400
        assert!(is_leap_year(2024)); // divisible by 4, not by 100
        assert!(!is_leap_year(1900)); // divisible by 100, not by 400
        assert!(!is_leap_year(2023)); // not divisible by 4
    }

    #[test]
    fn test_current_timestamp_format() {
        let ts = current_timestamp();
        // Should be in RFC3339 format: YYYY-MM-DDTHH:MM:SSZ
        assert!(ts.contains('T'));
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
    }
}
