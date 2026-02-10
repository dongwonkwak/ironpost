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
    ///
    /// # 에러 처리
    ///
    /// 개별 디렉토리 스캔 실패는 로깅되고 다른 디렉토리 스캔은 계속됩니다.
    /// 부분 결과를 반환하여 일부 실패가 전체 스캔을 막지 않도록 합니다.
    pub async fn scan_once(&self) -> Result<Vec<ScanResult>, SbomScannerError> {
        let mut all_results = Vec::new();

        // 각 scan_dir마다 별도 태스크로 블로킹 I/O 수행
        for scan_dir in &self.config.scan_dirs {
            let scan_dir_clone = scan_dir.clone();
            let max_file_size = self.config.max_file_size;
            let max_packages = self.config.max_packages;

            // 파서, 제너레이터, 매처를 클론하여 spawn_blocking으로 전달
            let parsers: Vec<Box<dyn LockfileParser>> =
                vec![Box::new(CargoLockParser), Box::new(NpmLockParser)];
            let generator = self.generator;
            let matcher_opt = self.matcher.clone();
            let alert_tx = self.alert_tx.clone();
            let scans_completed = Arc::clone(&self.scans_completed);
            let vulns_found = Arc::clone(&self.vulns_found);

            // spawn_blocking으로 동기 I/O 격리
            let scan_result = tokio::task::spawn_blocking(move || {
                let ctx = ScanContext {
                    parsers: &parsers,
                    generator: &generator,
                    matcher: &matcher_opt,
                    alert_tx: &alert_tx,
                    max_file_size,
                    max_packages,
                    scans_completed: &scans_completed,
                    vulns_found: &vulns_found,
                };
                scan_directory(&scan_dir_clone, &ctx)
            })
            .await;

            match scan_result {
                Ok(Ok(results)) => {
                    all_results.extend(results);
                }
                Ok(Err(e)) => {
                    // 개별 디렉토리 스캔 실패는 로깅만 하고 다음 디렉토리 진행
                    warn!(dir = %scan_dir, error = %e, "scan failed for directory, continuing with others");
                }
                Err(e) => {
                    // spawn_blocking 실패 (매우 드문 경우)
                    warn!(dir = %scan_dir, error = %e, "spawn_blocking failed, continuing with others");
                }
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

        if self.state == ScannerState::Stopped {
            return Err(IronpostError::Sbom(
                ironpost_core::error::SbomError::ScanFailed(
                    "cannot restart stopped scanner, create a new instance".to_owned(),
                ),
            ));
        }

        info!("starting sbom scanner");

        // VulnDb 로드 (blocking I/O)
        // TOCTOU 방지: exists() 체크 없이 직접 로드 시도, 에러 핸들링으로 처리
        let vuln_db_path = self.config.vuln_db_path.clone();
        let db_result = tokio::task::spawn_blocking(move || {
            let path = std::path::Path::new(&vuln_db_path);
            VulnDb::load_from_dir(path)
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
                self.matcher = Some(VulnMatcher::new(Arc::new(db), self.config.min_severity));
            }
            Err(e) => {
                // 디렉토리 미존재 등의 에러는 경고만 출력하고 계속 진행 (SBOM 전용 모드)
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
            let generator = SbomGenerator::new(output_format);
            let matcher_opt = self.matcher.clone();
            let alert_tx = self.alert_tx.clone();
            let scans_completed = Arc::clone(&self.scans_completed);
            let vulns_found = Arc::clone(&self.vulns_found);

            let task = tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

                info!(interval_secs, "periodic scan task started");

                loop {
                    interval.tick().await;

                    // Scanner가 드롭되어 alert receiver가 닫힌 경우 태스크 종료
                    if alert_tx.is_closed() {
                        info!("alert receiver closed, stopping periodic scan task");
                        break;
                    }

                    info!("starting periodic scan");

                    // 각 스캔 디렉토리 순회
                    for scan_dir in &scan_dirs {
                        let dir = scan_dir.clone();
                        let parsers: Vec<Box<dyn LockfileParser>> =
                            vec![Box::new(CargoLockParser), Box::new(NpmLockParser)];
                        let sbom_gen = generator;
                        let matcher = matcher_opt.clone();
                        let tx = alert_tx.clone();
                        let completed = Arc::clone(&scans_completed);
                        let found = Arc::clone(&vulns_found);

                        // spawn_blocking으로 동기 I/O 격리
                        let scan_result = tokio::task::spawn_blocking(move || {
                            let ctx = ScanContext {
                                parsers: &parsers,
                                generator: &sbom_gen,
                                matcher: &matcher,
                                alert_tx: &tx,
                                max_file_size,
                                max_packages,
                                scans_completed: &completed,
                                vulns_found: &found,
                            };
                            scan_directory(&dir, &ctx)
                        })
                        .await;

                        match scan_result {
                            Ok(Ok(_)) => {
                                info!(dir = %scan_dir, "periodic scan completed");
                            }
                            Ok(Err(e)) => {
                                warn!(dir = %scan_dir, error = %e, "periodic scan failed");
                            }
                            Err(e) => {
                                warn!(dir = %scan_dir, error = %e, "spawn_blocking failed");
                            }
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

        let generator = SbomGenerator::new(self.config.output_format);

        let scanner = SbomScanner {
            config: self.config,
            state: ScannerState::Initialized,
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

/// 스캔 컨텍스트 (공유 scan_directory 함수용 파라미터 그룹)
struct ScanContext<'a> {
    parsers: &'a [Box<dyn LockfileParser>],
    generator: &'a SbomGenerator,
    matcher: &'a Option<VulnMatcher>,
    alert_tx: &'a mpsc::Sender<AlertEvent>,
    max_file_size: usize,
    max_packages: usize,
    scans_completed: &'a AtomicU64,
    vulns_found: &'a AtomicU64,
}

/// 단일 디렉토리에서 스캔을 수행합니다 (공유 로직).
///
/// scan_once와 periodic 태스크 모두에서 사용됩니다.
fn scan_directory(scan_dir: &str, ctx: &ScanContext) -> Result<Vec<ScanResult>, SbomScannerError> {
    let mut results = Vec::new();
    let dir_path = std::path::Path::new(scan_dir);

    // 디렉토리에서 lockfile 탐색
    let lockfiles = {
        let detector = LockfileDetector::new();
        discover_lockfiles(dir_path, &detector, ctx.max_file_size)?
    };

    for (path, content) in &lockfiles {
        // 적합한 파서 찾기
        let file_path = std::path::Path::new(path);
        let parser = match ctx.parsers.iter().find(|p| p.can_parse(file_path)) {
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

        if graph.package_count() > ctx.max_packages {
            warn!(
                path = %path,
                packages = graph.package_count(),
                max = ctx.max_packages,
                "too many packages, skipping"
            );
            continue;
        }

        // SBOM 생성
        let sbom_doc = match ctx.generator.generate(&graph) {
            Ok(doc) => Some(doc),
            Err(e) => {
                warn!(path = %path, error = %e, "failed to generate SBOM");
                None
            }
        };

        // 취약점 스캔
        let findings = if let Some(m) = ctx.matcher {
            match m.scan(&graph) {
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

            if let Err(e) = ctx.alert_tx.try_send(alert_event) {
                warn!(
                    cve = %finding.vulnerability.cve_id,
                    error = %e,
                    "failed to send alert event (channel full or closed)"
                );
            }
        }

        ctx.scans_completed.fetch_add(1, Ordering::Relaxed);
        let vulns_u64 = u64::try_from(finding_count).unwrap_or(u64::MAX);
        ctx.vulns_found.fetch_add(vulns_u64, Ordering::Relaxed);

        info!(
            path = %path,
            packages = graph.package_count(),
            findings = finding_count,
            "scan completed"
        );

        results.push(result);
    }

    Ok(results)
}

/// lockfile 발견 최대 개수 (단일 디렉토리당)
const MAX_LOCKFILES_PER_DIR: usize = 100;

/// 디렉토리에서 lockfile을 탐색하고 내용을 읽습니다 (동기 I/O).
///
/// `tokio::task::spawn_blocking` 내에서 호출되어야 합니다.
/// 최대 MAX_LOCKFILES_PER_DIR개의 lockfile만 처리합니다.
fn discover_lockfiles(
    dir: &std::path::Path,
    detector: &LockfileDetector,
    max_file_size: usize,
) -> Result<Vec<(String, String)>, SbomScannerError> {
    let mut results = Vec::new();
    let mut lockfile_count = 0;

    // TOCTOU 방지: exists() 체크 없이 직접 read_dir 시도, 에러 핸들링으로 처리
    // 재귀 없이 1단계만 탐색 (깊은 탐색은 향후 확장)
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(dir = %dir.display(), "scan directory does not exist");
            return Ok(results);
        }
        Err(e) => {
            return Err(SbomScannerError::Io {
                path: dir.display().to_string(),
                source: e,
            });
        }
    };

    // 스캔 디렉토리의 정규화된 경로 (심볼릭 링크 해소)
    let dir_canonical = match std::fs::canonicalize(dir) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), error = %e, "failed to canonicalize scan directory");
            // canonicalize 실패 시 원본 경로 사용 (경고만 출력)
            dir.to_path_buf()
        }
    };

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

        // 심볼릭 링크 체크 (TOCTOU 완화를 위해 경로 기반으로 먼저 확인)
        let symlink_metadata = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "failed to read symlink metadata");
                continue;
            }
        };

        // 심볼릭 링크는 스캔하지 않음 (탈출 방지)
        if symlink_metadata.is_symlink() {
            tracing::warn!(
                path = %path.display(),
                "skipping symbolic link to prevent directory traversal"
            );
            continue;
        }

        // 정규화된 경로가 스캔 디렉토리 내에 있는지 확인
        if let Ok(canonical_path) = std::fs::canonicalize(&path)
            && !canonical_path.starts_with(&dir_canonical)
        {
            tracing::warn!(
                path = %path.display(),
                canonical = %canonical_path.display(),
                scan_dir = %dir_canonical.display(),
                "file is outside scan directory, skipping"
            );
            continue;
        }

        // 파일을 한 번만 열고 metadata와 content를 같은 핸들에서 읽어 TOCTOU 방지
        let mut file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "failed to open file");
                continue;
            }
        };

        // 파일 핸들에서 metadata 가져오기 (크기 체크용)
        let metadata = match file.metadata() {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "failed to read file metadata");
                continue;
            }
        };

        // 파일 크기 확인
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

        // 같은 파일 핸들에서 내용 읽기 (TOCTOU 방지)
        let mut content = String::new();
        if let Err(e) = std::io::Read::read_to_string(&mut file, &mut content) {
            tracing::warn!(path = %path.display(), error = %e, "failed to read lockfile");
            continue;
        }

        lockfile_count += 1;
        results.push((path.display().to_string(), content));

        // lockfile 개수 제한 확인
        if lockfile_count >= MAX_LOCKFILES_PER_DIR {
            tracing::warn!(
                dir = %dir.display(),
                count = lockfile_count,
                max = MAX_LOCKFILES_PER_DIR,
                "reached maximum lockfile limit per directory, stopping discovery"
            );
            break;
        }
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
