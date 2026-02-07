//! 설정 관리 — ironpost.toml 파싱 및 런타임 설정

use serde::{Deserialize, Serialize};

/// Ironpost 통합 설정
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IronpostConfig {
    /// 일반 설정
    pub general: GeneralConfig,
    /// eBPF 엔진 설정
    pub ebpf: EbpfConfig,
    /// 로그 파이프라인 설정
    pub log_pipeline: LogPipelineConfig,
    /// 컨테이너 가드 설정
    pub container: ContainerConfig,
    /// SBOM 스캐너 설정
    pub sbom: SbomConfig,
}

/// 일반 설정
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// 로그 레벨
    pub log_level: String,
    /// 로그 형식 (json, pretty)
    pub log_format: String,
    /// 데이터 디렉토리
    pub data_dir: String,
    /// PID 파일 경로
    pub pid_file: String,
}

/// eBPF 엔진 설정
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfConfig {
    /// 활성화 여부
    pub enabled: bool,
    /// 감시할 네트워크 인터페이스
    pub interface: String,
    /// XDP 모드 (native, skb, hw)
    pub xdp_mode: String,
    /// 이벤트 링 버퍼 크기 (바이트)
    pub ring_buffer_size: usize,
    /// 차단 목록 최대 엔트리 수
    pub blocklist_max_entries: usize,
}

/// 로그 파이프라인 설정
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogPipelineConfig {
    /// 활성화 여부
    pub enabled: bool,
    /// 수집 소스
    pub sources: Vec<String>,
    /// Syslog 수신 주소
    pub syslog_bind: String,
    /// 파일 감시 경로
    pub watch_paths: Vec<String>,
    /// 배치 크기
    pub batch_size: usize,
    /// 배치 플러시 간격 (초)
    pub flush_interval_secs: u64,
    /// 스토리지 설정
    pub storage: StorageConfig,
}

/// 스토리지 설정
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// PostgreSQL 연결 문자열
    pub postgres_url: String,
    /// Redis 연결 문자열
    pub redis_url: String,
    /// 로그 보존 기간 (일)
    pub retention_days: u32,
}

/// 컨테이너 가드 설정
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerConfig {
    /// 활성화 여부
    pub enabled: bool,
    /// Docker 소켓 경로
    pub docker_socket: String,
    /// 모니터링 주기 (초)
    pub poll_interval_secs: u64,
    /// 격리 정책 파일 경로
    pub policy_path: String,
    /// 자동 격리 활성화
    pub auto_isolate: bool,
}

/// SBOM 스캐너 설정
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomConfig {
    /// 활성화 여부
    pub enabled: bool,
    /// 스캔 대상 디렉토리
    pub scan_dirs: Vec<String>,
    /// 취약점 DB 업데이트 주기 (시간)
    pub vuln_db_update_hours: u32,
    /// 취약점 DB 경로
    pub vuln_db_path: String,
    /// 최소 심각도 알림 수준
    pub min_severity: String,
    /// SBOM 출력 형식 (spdx, cyclonedx)
    pub output_format: String,
}
