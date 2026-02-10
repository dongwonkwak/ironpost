//! SBOM 스캐너 오케스트레이터 -- 전체 스캔 흐름 관리
//!
//! [`SbomScanner`]는 core의 [`Pipeline`] trait을 구현하여
//! `ironpost-daemon`에서 다른 모듈과 동일한 생명주기로 관리됩니다.
//!
//! # 내부 아키텍처
//!
//! ```text
//! scan_dirs --> LockfileDetector --> LockfileParser --> PackageGraph
//!                                                          |
//!                                    +---------------------+---------------------+
//!                                    |                                           |
//!                              SbomGenerator                                VulnMatcher
//!                                    |                                           |
//!                              SbomDocument                               Vec<ScanFinding>
//!                                                                               |
//!                                                                         AlertEvent
//!                                                                               |
//!                                                                      mpsc --> downstream
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use ironpost_core::error::IronpostError;
use ironpost_core::event::AlertEvent;
use ironpost_core::pipeline::{HealthStatus, Pipeline};
use ironpost_core::types::Alert;

use crate::config::SbomScannerConfig;
use crate::error::SbomScannerError;
use crate::parser::cargo::CargoLockParser;
use crate::parser::npm::NpmLockParser;
use crate::parser::{LockfileDetector, LockfileParser};
use crate::sbom::SbomGenerator;
use crate::vuln::{ScanResult, VulnDb, VulnMatcher};

/// 스캐너 실행 상태
#[derive(Debug, Clone, PartialEq, Eq)]
enum ScannerState {
    /// 초기화됨, 아직 시작하지 않음
    Initialized,
    /// 실행 중
    Running,
    /// 정지됨
    Stopped,
}

/// SBOM 스캐너 오케스트레이터
///
/// 의존성 파일 탐색, SBOM 생성, 취약점 스캔, 알림 전송의 전체 흐름을 관리합니다.
/// core의 `Pipeline` trait을 구현하여 생명주기(start/stop/health_check)를 제공합니다.
///
/// # 재시작 제한
///
/// `stop()` 후 재시작이 필요하면 `SbomScannerBuilder`로 새 인스턴스를 생성해야 합니다.
pub struct SbomScanner {
    /// 스캐너 설정
    config: SbomScannerConfig,
    /// 현재 상태
    state: ScannerState,
    /// lockfile 파서 목록
    parsers: Vec<Box<dyn LockfileParser>>,
    /// SBOM 생성기
    generator: SbomGenerator,
    /// 취약점 매처 (VulnDb 로드 후 설정)
    matcher: Option<VulnMatcher>,
    /// 알림 전송 채널
    alert_tx: mpsc::Sender<AlertEvent>,
    /// 백그라운드 태스크 핸들
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// 완료된 스캔 수
    scans_completed: Arc<AtomicU64>,
    /// 발견된 취약점 수
    vulns_found: Arc<AtomicU64>,
    /// VulnDb 로드 여부
    vuln_db_loaded: bool,
}

impl SbomScanner {
    /// 현재 상태명을 반환합니다.
    pub fn state_name(&self) -> &str {
        match self.state {
            ScannerState::Initialized => "initialized",
            ScannerState::Running => "running",
            ScannerState::Stopped => "stopped",
        }
    }

    /// 완료된 스캔 수를 반환합니다.
    pub fn scans_completed(&self) -> u64 {
        self.scans_completed.load(Ordering::Relaxed)
    }

    /// 발견된 취약점 수를 반환합니다.
    pub fn vulns_found(&self) -> u64 {
        self.vulns_found.load(Ordering::Relaxed)
    }

    /// VulnDb가 로드되었는지 반환합니다.
    pub fn is_vuln_db_loaded(&self) -> bool {
        self.vuln_db_loaded
    }

    /// 단일 스캔을 수행합니다 (수동 트리거용).
    ///
    /// 설정된 모든 scan_dirs를 스캔하고 결과를 반환합니다.
    /// 발견된 취약점은 AlertEvent로 자동 전송됩니다.
    pub async fn scan_once(&self) -> Result<Vec<ScanResult>, SbomScannerError> {
        let mut all_results = Vec::new();

        for scan_dir in &self.config.scan_dirs {
            let dir_path = std::path::Path::new(scan_dir);

            // 디렉토리에서 lockfile 탐색 (blocking I/O)
            let lockfiles = {
                let dir = dir_path.to_path_buf();
                let detector = LockfileDetector::new();
                let max_file_size = self.config.max_file_size;
                tokio::task::spawn_blocking(move || {
                    discover_lockfiles(&dir, &detector, max_file_size)
                })
                .await
                .map_err(|e| SbomScannerError::Channel(format!("spawn_blocking failed: {e}")))?
            }?;

            for (path, content) in &lockfiles {
                // 적합한 파서 찾기
                let file_path = std::path::Path::new(path);
                let parser = match self.parsers.iter().find(|p| p.can_parse(file_path)) {
                    Some(p) => p,
                    None => {
                        debug!(path = %path, "no parser found for lockfile, skipping");
                        continue;
                    }
                };

                // 패키지 그래프 파싱
                let graph = match parser.parse(content, path) {
                    Ok(g) => g,
                    Err(e) => {
                        warn!(path = %path, error = %e, "failed to parse lockfile, skipping");
                        continue;
                    }
                };

                if graph.package_count() > self.config.max_packages {
                    warn!(
                        path = %path,
                        packages = graph.package_count(),
                        max = self.config.max_packages,
                        "too many packages, skipping"
                    );
                    continue;
                }

                // SBOM 생성
                let sbom_doc = match self.generator.generate(&graph) {
                    Ok(doc) => Some(doc),
                    Err(e) => {
                        warn!(path = %path, error = %e, "failed to generate SBOM");
                        None
                    }
                };

                // 취약점 스캔
                let findings = if let Some(ref matcher) = self.matcher {
                    match matcher.scan(&graph) {
                        Ok(f) => f,
                        Err(e) => {
                            warn!(path = %path, error = %e, "vulnerability scan failed");
                            Vec::new()
                        }
                    }
                } else {
                    debug!("no vuln db loaded, skipping vulnerability scan");
                    Vec::new()
                };

                let finding_count = findings.len();

                let result = ScanResult {
                    scan_id: uuid::Uuid::new_v4().to_string(),
                    source_file: path.clone(),
                    ecosystem: graph.ecosystem,
                    total_packages: graph.package_count(),
                    findings,
                    sbom_document: sbom_doc,
                    scanned_at: SystemTime::now(),
                };

                // AlertEvent 전송
                for finding in &result.findings {
                    let alert = Alert {
                        id: uuid::Uuid::new_v4().to_string(),
                        title: format!(
                            "{}: {} in {}",
                            finding.vulnerability.cve_id,
                            finding.vulnerability.description,
                            finding.vulnerability.package,
                        ),
                        description: format!(
                            "Package {} version {} is affected by {}. Fixed in: {}",
                            finding.vulnerability.package,
                            finding.vulnerability.affected_version,
                            finding.vulnerability.cve_id,
                            finding
                                .vulnerability
                                .fixed_version
                                .as_deref()
                                .unwrap_or("N/A"),
                        ),
                        severity: finding.vulnerability.severity,
                        rule_name: "sbom_vuln_scan".to_owned(),
                        source_ip: None,
                        target_ip: None,
                        created_at: SystemTime::now(),
                    };

                    let alert_event = AlertEvent::new(alert, finding.vulnerability.severity);

                    if let Err(e) = self.alert_tx.try_send(alert_event) {
                        warn!(
                            cve = %finding.vulnerability.cve_id,
                            error = %e,
                            "failed to send alert event (channel full or closed)"
                        );
                    }
                }

                self.scans_completed.fetch_add(1, Ordering::Relaxed);
                let vulns_u64 = u64::try_from(finding_count).unwrap_or(u64::MAX);
                self.vulns_found.fetch_add(vulns_u64, Ordering::Relaxed);

                info!(
                    path = %path,
                    packages = graph.package_count(),
                    findings = finding_count,
                    "scan completed"
                );

                all_results.push(result);
            }
        }

        Ok(all_results)
    }
}

impl Pipeline for SbomScanner {
    async fn start(&mut self) -> Result<(), IronpostError> {
        if self.state == ScannerState::Running {
            return Err(ironpost_core::error::PipelineError::AlreadyRunning.into());
        }

        info!("starting sbom scanner");

        // VulnDb 로드 (blocking I/O)
        let vuln_db_path = self.config.vuln_db_path.clone();
        let db_result = tokio::task::spawn_blocking(move || {
            let path = std::path::Path::new(&vuln_db_path);
            if path.exists() {
                VulnDb::load_from_dir(path)
            } else {
                tracing::warn!(path = %vuln_db_path, "vuln db directory not found");
                Ok(VulnDb::empty())
            }
        })
        .await
        .map_err(|e| {
            IronpostError::Sbom(ironpost_core::error::SbomError::VulnDb(format!(
                "spawn_blocking failed: {e}"
            )))
        })?;

        match db_result {
            Ok(db) => {
                let entry_count = db.entry_count();
                if entry_count > 0 {
                    info!(entries = entry_count, "vulnerability database loaded");
                    self.vuln_db_loaded = true;
                } else {
                    warn!("vulnerability database is empty, running in SBOM-only mode");
                }
                self.matcher = Some(VulnMatcher::new(
                    Arc::new(db),
                    self.config.min_severity,
                ));
            }
            Err(e) => {
                warn!(error = %e, "failed to load vulnerability database, running in degraded mode");
            }
        }

        // 주기적 스캔 태스크 스폰 (scan_interval_secs > 0인 경우)
        if self.config.scan_interval_secs > 0 {
            let interval_secs = self.config.scan_interval_secs;
            let scan_dirs = self.config.scan_dirs.clone();
            let max_file_size = self.config.max_file_size;
            let max_packages = self.config.max_packages;
            let output_format = self.config.output_format;

            // 공유 컴포넌트
            let parsers: Vec<Box<dyn LockfileParser>> = vec![
                Box::new(CargoLockParser),
                Box::new(NpmLockParser),
            ];
            let generator = SbomGenerator::new(output_format);
            let matcher_opt = self.matcher.clone();
            let alert_tx = self.alert_tx.clone();
            let scans_completed = Arc::clone(&self.scans_completed);
            let vulns_found = Arc::clone(&self.vulns_found);

            let task = tokio::spawn(async move {
                let mut interval = tokio::time::interval(
                    tokio::time::Duration::from_secs(interval_secs)
                );

                info!(interval_secs, "periodic scan task started");

                loop {
                    interval.tick().await;

                    info!("starting periodic scan");

                    // 각 스캔 디렉토리 순회
                    for scan_dir in &scan_dirs {
                        let dir_path = std::path::Path::new(scan_dir);

                        // lockfile 탐색
                        let lockfiles_result = {
                            let dir = dir_path.to_path_buf();
                            let detector = LockfileDetector::new();
                            tokio::task::spawn_blocking(move || {
                                discover_lockfiles(&dir, &detector, max_file_size)
                            })
                            .await
                        };

                        let lockfiles = match lockfiles_result {
                            Ok(Ok(files)) => files,
                            Ok(Err(e)) => {
                                warn!(dir = %scan_dir, error = %e, "failed to discover lockfiles");
                                continue;
                            }
                            Err(e) => {
                                warn!(error = %e, "spawn_blocking failed");
                                continue;
                            }
                        };

                        for (path, content) in &lockfiles {
                            let file_path = std::path::Path::new(path);
                            let parser = match parsers.iter().find(|p| p.can_parse(file_path)) {
                                Some(p) => p,
                                None => {
                                    debug!(path = %path, "no parser found");
                                    continue;
                                }
                            };

                            // 패키지 그래프 파싱
                            let graph = match parser.parse(content, path) {
                                Ok(g) => g,
                                Err(e) => {
                                    warn!(path = %path, error = %e, "parse failed");
                                    continue;
                                }
                            };

                            if graph.package_count() > max_packages {
                                warn!(path = %path, packages = graph.package_count(), "too many packages");
                                continue;
                            }

                            // SBOM 생성
                            let _sbom_doc = match generator.generate(&graph) {
                                Ok(doc) => Some(doc),
                                Err(e) => {
                                    warn!(path = %path, error = %e, "SBOM generation failed");
                                    None
                                }
                            };

                            // 취약점 스캔
                            let findings = if let Some(ref matcher) = matcher_opt {
                                match matcher.scan(&graph) {
                                    Ok(f) => f,
                                    Err(e) => {
                                        warn!(path = %path, error = %e, "vulnerability scan failed");
                                        Vec::new()
                                    }
                                }
                            } else {
                                Vec::new()
                            };

                            let finding_count = findings.len();

                            // AlertEvent 전송
                            for finding in &findings {
                                let alert = Alert {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    title: format!(
                                        "{}: {} in {}",
                                        finding.vulnerability.cve_id,
                                        finding.vulnerability.description,
                                        finding.vulnerability.package,
                                    ),
                                    description: format!(
                                        "Package {} version {} is affected by {}. Fixed in: {}",
                                        finding.vulnerability.package,
                                        finding.vulnerability.affected_version,
                                        finding.vulnerability.cve_id,
                                        finding
                                            .vulnerability
                                            .fixed_version
                                            .as_deref()
                                            .unwrap_or("N/A"),
                                    ),
                                    severity: finding.vulnerability.severity,
                                    rule_name: "sbom_vuln_scan".to_owned(),
                                    source_ip: None,
                                    target_ip: None,
                                    created_at: SystemTime::now(),
                                };

                                let alert_event = AlertEvent::new(alert, finding.vulnerability.severity);

                                if let Err(e) = alert_tx.try_send(alert_event) {
                                    warn!(cve = %finding.vulnerability.cve_id, error = %e, "failed to send alert");
                                }
                            }

                            scans_completed.fetch_add(1, Ordering::Relaxed);
                            let vulns_u64 = u64::try_from(finding_count).unwrap_or(u64::MAX);
                            vulns_found.fetch_add(vulns_u64, Ordering::Relaxed);

                            info!(
                                path = %path,
                                packages = graph.package_count(),
                                findings = finding_count,
                                "periodic scan completed"
                            );
                        }
                    }
                }
            });

            self.tasks.push(task);
            info!(interval_secs, "periodic scan task spawned");
        }

        self.state = ScannerState::Running;
        info!("sbom scanner started");
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), IronpostError> {
        if self.state != ScannerState::Running {
            return Err(ironpost_core::error::PipelineError::NotRunning.into());
        }

        info!("stopping sbom scanner");

        for task in self.tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }

        self.state = ScannerState::Stopped;
        info!("sbom scanner stopped");
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        match self.state {
            ScannerState::Running => {
                if self.vuln_db_loaded {
                    HealthStatus::Healthy
                } else {
                    HealthStatus::Degraded(
                        "vulnerability database not loaded, SBOM-only mode".to_owned(),
                    )
                }
            }
            ScannerState::Initialized => HealthStatus::Unhealthy("not started".to_owned()),
            ScannerState::Stopped => HealthStatus::Unhealthy("stopped".to_owned()),
        }
    }
}

/// SBOM 스캐너 빌더
///
/// 스캐너를 구성하고 필요한 채널을 생성합니다.
pub struct SbomScannerBuilder {
    config: SbomScannerConfig,
    alert_tx: Option<mpsc::Sender<AlertEvent>>,
    alert_channel_capacity: usize,
}

impl SbomScannerBuilder {
    /// 새 빌더를 생성합니다.
    pub fn new() -> Self {
        Self {
            config: SbomScannerConfig::default(),
            alert_tx: None,
            alert_channel_capacity: 256,
        }
    }

    /// 스캐너 설정을 지정합니다.
    pub fn config(mut self, config: SbomScannerConfig) -> Self {
        self.config = config;
        self
    }

    /// 외부 알림 전송 채널을 설정합니다.
    ///
    /// 설정하지 않으면 빌더가 새 채널을 생성합니다.
    pub fn alert_sender(mut self, tx: mpsc::Sender<AlertEvent>) -> Self {
        self.alert_tx = Some(tx);
        self
    }

    /// 알림 채널 용량을 설정합니다 (외부 채널 미사용 시).
    pub fn alert_channel_capacity(mut self, capacity: usize) -> Self {
        self.alert_channel_capacity = capacity;
        self
    }

    /// 스캐너를 빌드합니다.
    ///
    /// # Returns
    ///
    /// - `SbomScanner`: 스캐너 인스턴스
    /// - `Option<mpsc::Receiver<AlertEvent>>`: 알림 수신 채널
    ///   (외부 alert_sender를 설정한 경우 None)
    pub fn build(
        self,
    ) -> Result<(SbomScanner, Option<mpsc::Receiver<AlertEvent>>), SbomScannerError> {
        self.config.validate()?;

        let (alert_tx, alert_rx) = if let Some(tx) = self.alert_tx {
            (tx, None)
        } else {
            let (tx, rx) = mpsc::channel(self.alert_channel_capacity);
            (tx, Some(rx))
        };

        // 기본 파서 등록
        let parsers: Vec<Box<dyn LockfileParser>> = vec![
            Box::new(CargoLockParser),
            Box::new(NpmLockParser),
        ];

        let generator = SbomGenerator::new(self.config.output_format);

        let scanner = SbomScanner {
            config: self.config,
            state: ScannerState::Initialized,
            parsers,
            generator,
            matcher: None, // VulnDb는 start()에서 로드
            alert_tx,
            tasks: Vec::new(),
            scans_completed: Arc::new(AtomicU64::new(0)),
            vulns_found: Arc::new(AtomicU64::new(0)),
            vuln_db_loaded: false,
        };

        Ok((scanner, alert_rx))
    }
}

impl Default for SbomScannerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// 디렉토리에서 lockfile을 탐색하고 내용을 읽습니다 (동기 I/O).
///
/// `tokio::task::spawn_blocking` 내에서 호출되어야 합니다.
fn discover_lockfiles(
    dir: &std::path::Path,
    detector: &LockfileDetector,
    max_file_size: usize,
) -> Result<Vec<(String, String)>, SbomScannerError> {
    let mut results = Vec::new();

    if !dir.exists() {
        tracing::warn!(dir = %dir.display(), "scan directory does not exist");
        return Ok(results);
    }

    // 재귀 없이 1단계만 탐색 (깊은 탐색은 향후 확장)
    let entries = std::fs::read_dir(dir).map_err(|e| SbomScannerError::Io {
        path: dir.display().to_string(),
        source: e,
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

        if !detector.is_lockfile(&path) {
            continue;
        }

        // 파일 크기 확인
        let metadata = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "failed to read file metadata");
                continue;
            }
        };

        let file_size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        if file_size > max_file_size {
            tracing::warn!(
                path = %path.display(),
                size = file_size,
                max = max_file_size,
                "lockfile too large, skipping"
            );
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "failed to read lockfile");
                continue;
            }
        };

        results.push((path.display().to_string(), content));
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_creates_scanner() {
        let (scanner, alert_rx) = SbomScannerBuilder::new().build().unwrap();
        assert_eq!(scanner.state_name(), "initialized");
        assert!(alert_rx.is_some());
    }

    #[test]
    fn builder_with_external_alert_sender() {
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let (_scanner, rx) = SbomScannerBuilder::new()
            .alert_sender(alert_tx)
            .build()
            .unwrap();
        assert!(rx.is_none());
    }

    #[test]
    fn builder_rejects_invalid_config() {
        let result = SbomScannerBuilder::new()
            .config(SbomScannerConfig {
                max_file_size: 0, // invalid
                ..Default::default()
            })
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn scanner_initial_metrics() {
        let (scanner, _) = SbomScannerBuilder::new().build().unwrap();
        assert_eq!(scanner.scans_completed(), 0);
        assert_eq!(scanner.vulns_found(), 0);
        assert!(!scanner.is_vuln_db_loaded());
    }

    #[tokio::test]
    async fn scanner_health_check_before_start() {
        let (scanner, _) = SbomScannerBuilder::new().build().unwrap();
        assert!(scanner.health_check().await.is_unhealthy());
    }

    #[tokio::test]
    async fn scanner_double_stop_fails() {
        let (mut scanner, _) = SbomScannerBuilder::new().build().unwrap();
        let err = scanner.stop().await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn scanner_start_stop_lifecycle() {
        let (mut scanner, _) = SbomScannerBuilder::new().build().unwrap();

        // Start
        scanner.start().await.unwrap();
        assert_eq!(scanner.state_name(), "running");

        // Double start fails
        assert!(scanner.start().await.is_err());

        // Stop
        scanner.stop().await.unwrap();
        assert_eq!(scanner.state_name(), "stopped");

        // Double stop fails
        assert!(scanner.stop().await.is_err());
    }

    #[tokio::test]
    async fn scanner_health_check_running_no_db() {
        let (mut scanner, _) = SbomScannerBuilder::new().build().unwrap();
        scanner.start().await.unwrap();

        // Without vuln DB, should be degraded
        let status = scanner.health_check().await;
        assert!(!status.is_healthy() || !scanner.is_vuln_db_loaded());

        scanner.stop().await.unwrap();
    }

    #[tokio::test]
    async fn scanner_scan_once_empty_dir() {
        let (mut scanner, _alert_rx) = SbomScannerBuilder::new()
            .config(SbomScannerConfig {
                scan_dirs: vec!["/nonexistent/path/for/test".to_owned()],
                ..Default::default()
            })
            .build()
            .unwrap();

        scanner.start().await.unwrap();

        let results = scanner.scan_once().await.unwrap();
        assert!(results.is_empty());

        scanner.stop().await.unwrap();
    }
}
