//! 의존성 파일 파서 -- Cargo.lock, package-lock.json 등
//!
//! [`LockfileParser`] trait은 각 lockfile 형식의 파서가 구현해야 하는 인터페이스입니다.
//! [`LockfileDetector`]는 디렉토리를 스캔하여 지원되는 lockfile을 찾습니다.
//!
//! # 지원 형식
//!
//! - `Cargo.lock` (TOML) -- [`CargoLockParser`]
//! - `package-lock.json` (JSON) -- [`NpmLockParser`]
//!
//! # 확장
//!
//! 새로운 형식을 지원하려면 `LockfileParser` trait을 구현하고
//! `LockfileDetector`에 등록합니다.

pub mod cargo;
pub mod npm;

use std::path::Path;

use crate::error::SbomScannerError;
use crate::types::{Ecosystem, PackageGraph};

/// Lockfile 파서 trait
///
/// 각 패키지 생태계의 lockfile 형식을 파싱하여 [`PackageGraph`]를 생성합니다.
pub trait LockfileParser: Send + Sync {
    /// 이 파서가 담당하는 생태계를 반환합니다.
    fn ecosystem(&self) -> Ecosystem;

    /// 주어진 경로의 파일을 이 파서가 처리할 수 있는지 확인합니다.
    ///
    /// 파일 이름 패턴으로 판별합니다 (예: "Cargo.lock", "package-lock.json").
    fn can_parse(&self, path: &Path) -> bool;

    /// lockfile 내용을 파싱하여 패키지 그래프를 반환합니다.
    ///
    /// # Arguments
    ///
    /// - `content`: lockfile 파일 내용 (UTF-8 문자열)
    /// - `source_path`: 원본 파일 경로 (에러 메시지용)
    fn parse(&self, content: &str, source_path: &str) -> Result<PackageGraph, SbomScannerError>;
}

/// Lockfile 탐지기
///
/// 디렉토리를 재귀적으로 스캔하여 지원되는 lockfile을 찾습니다.
/// 등록된 파서 목록을 기반으로 파일 이름 매칭을 수행합니다.
pub struct LockfileDetector {
    /// 알려진 lockfile 파일명 목록
    known_filenames: Vec<(String, Ecosystem)>,
}

impl LockfileDetector {
    /// 기본 lockfile 패턴으로 탐지기를 생성합니다.
    pub fn new() -> Self {
        Self {
            known_filenames: vec![
                ("Cargo.lock".to_owned(), Ecosystem::Cargo),
                ("package-lock.json".to_owned(), Ecosystem::Npm),
            ],
        }
    }

    /// 알려진 lockfile 파일명 목록을 반환합니다.
    pub fn known_filenames(&self) -> &[(String, Ecosystem)] {
        &self.known_filenames
    }

    /// 주어진 경로가 알려진 lockfile인지 확인합니다.
    pub fn is_lockfile(&self, path: &Path) -> bool {
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name,
            None => return false,
        };

        self.known_filenames
            .iter()
            .any(|(known, _)| known == file_name)
    }

    /// lockfile의 생태계를 반환합니다.
    pub fn detect_ecosystem(&self, path: &Path) -> Option<Ecosystem> {
        let file_name = path.file_name().and_then(|n| n.to_str())?;

        self.known_filenames
            .iter()
            .find(|(known, _)| known == file_name)
            .map(|(_, eco)| *eco)
    }
}

impl Default for LockfileDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn detector_recognizes_cargo_lock() {
        let detector = LockfileDetector::new();
        let path = PathBuf::from("/project/Cargo.lock");
        assert!(detector.is_lockfile(&path));
        assert_eq!(detector.detect_ecosystem(&path), Some(Ecosystem::Cargo));
    }

    #[test]
    fn detector_recognizes_package_lock_json() {
        let detector = LockfileDetector::new();
        let path = PathBuf::from("/project/package-lock.json");
        assert!(detector.is_lockfile(&path));
        assert_eq!(detector.detect_ecosystem(&path), Some(Ecosystem::Npm));
    }

    #[test]
    fn detector_rejects_unknown_file() {
        let detector = LockfileDetector::new();
        let path = PathBuf::from("/project/unknown.txt");
        assert!(!detector.is_lockfile(&path));
        assert_eq!(detector.detect_ecosystem(&path), None);
    }

    #[test]
    fn detector_rejects_empty_path() {
        let detector = LockfileDetector::new();
        let path = PathBuf::from("");
        assert!(!detector.is_lockfile(&path));
    }

    #[test]
    fn detector_known_filenames() {
        let detector = LockfileDetector::new();
        assert_eq!(detector.known_filenames().len(), 2);
    }
}
