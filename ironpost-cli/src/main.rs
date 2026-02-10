use anyhow::Result;
use clap::{Parser, Subcommand};
use std::sync::Arc;

use ironpost_container_guard::{
    BollardDockerClient, DockerClient, IsolationAction, IsolationExecutor,
};

/// Ironpost CLI — 통합 보안 모니터링 명령줄 도구
#[derive(Parser)]
#[command(name = "ironpost", version, about)]
struct Cli {
    /// 설정 파일 경로
    #[arg(short, long, default_value = "ironpost.toml")]
    config: String,

    /// 로그 레벨
    #[arg(short, long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// eBPF 엔진 관련 명령 (Linux 전용)
    #[cfg(target_os = "linux")]
    Ebpf {
        #[command(subcommand)]
        action: EbpfAction,
    },
    /// 로그 파이프라인 관련 명령
    Log {
        #[command(subcommand)]
        action: LogAction,
    },
    /// 컨테이너 가드 관련 명령
    Container {
        #[command(subcommand)]
        action: ContainerAction,
    },
    /// SBOM 스캐너 관련 명령
    Sbom {
        #[command(subcommand)]
        action: SbomAction,
    },
}

#[cfg(target_os = "linux")]
#[derive(Subcommand)]
enum EbpfAction {
    /// eBPF 엔진 상태 확인
    Status,
    /// 차단 목록 관리
    Blocklist,
    /// 통계 조회
    Stats,
}

#[derive(Subcommand)]
enum LogAction {
    /// 로그 파이프라인 상태 확인
    Status,
    /// 로그 검색
    Search {
        /// 검색 쿼리
        query: String,
    },
    /// 탐지 규칙 관리
    Rules,
}

#[derive(Subcommand)]
enum ContainerAction {
    /// 컨테이너 목록 조회
    List,
    /// 컨테이너 격리
    Isolate {
        /// 컨테이너 ID
        container_id: String,
    },
    /// 격리 해제
    Release {
        /// 컨테이너 ID
        container_id: String,
    },
}

#[derive(Subcommand)]
enum SbomAction {
    /// SBOM 생성
    Generate {
        /// 스캔 대상 경로
        path: String,
    },
    /// 취약점 스캔
    Scan {
        /// SBOM 파일 경로
        sbom_path: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(&cli.log_level)
        .json()
        .init();

    tracing::info!(config = %cli.config, "ironpost-cli starting");

    #[cfg(target_os = "linux")]
    if let Commands::Ebpf { action } = &cli.command {
        match action {
            EbpfAction::Status => {
                tracing::info!("ebpf status: not yet implemented");
            }
            EbpfAction::Blocklist => {
                tracing::info!("ebpf blocklist: not yet implemented");
            }
            EbpfAction::Stats => {
                tracing::info!("ebpf stats: not yet implemented");
            }
        }
        return Ok(());
    }

    match cli.command {
        #[cfg(target_os = "linux")]
        Commands::Ebpf { .. } => unreachable!(),
        Commands::Log { action } => match action {
            LogAction::Status => {
                tracing::info!("log pipeline status: not yet implemented");
            }
            LogAction::Search { query } => {
                tracing::info!(query = %query, "log search: not yet implemented");
            }
            LogAction::Rules => {
                tracing::info!("log rules: not yet implemented");
            }
        },
        Commands::Container { action } => {
            handle_container_command(action).await?;
        }
        Commands::Sbom { action } => match action {
            SbomAction::Generate { path } => {
                tracing::info!(path = %path, "sbom generate: not yet implemented");
            }
            SbomAction::Scan { sbom_path } => {
                tracing::info!(path = %sbom_path, "sbom scan: not yet implemented");
            }
        },
    }

    Ok(())
}

async fn handle_container_command(action: ContainerAction) -> Result<()> {
    let docker = Arc::new(
        BollardDockerClient::connect_local()
            .map_err(|e| anyhow::anyhow!("failed to connect to docker: {}", e))?,
    );

    match action {
        ContainerAction::List => {
            let containers = docker
                .list_containers()
                .await
                .map_err(|e| anyhow::anyhow!("failed to list containers: {}", e))?;

            println!("Container List:");
            println!(
                "{:<12} {:<30} {:<40} {:<10}",
                "ID", "Name", "Image", "Status"
            );
            println!("{}", "-".repeat(92));

            for container in containers {
                let short_id = if container.id.len() > 12 {
                    &container.id[..12]
                } else {
                    &container.id
                };
                println!(
                    "{:<12} {:<30} {:<40} {:<10}",
                    short_id, container.name, container.image, container.status
                );
            }
        }
        ContainerAction::Isolate { container_id } => {
            println!("Isolating container: {}", container_id);

            let (action_tx, _action_rx) = tokio::sync::mpsc::channel(16);
            let executor = IsolationExecutor::new(
                Arc::clone(&docker),
                action_tx,
                std::time::Duration::from_secs(30),
                3,
                std::time::Duration::from_millis(100),
            );

            executor
                .execute(&container_id, &IsolationAction::Pause, "cli-manual")
                .await
                .map_err(|e| anyhow::anyhow!("failed to isolate container: {}", e))?;

            println!("✓ Container {} isolated (paused)", container_id);
        }
        ContainerAction::Release { container_id } => {
            println!("Releasing container: {}", container_id);

            docker
                .unpause_container(&container_id)
                .await
                .map_err(|e| anyhow::anyhow!("failed to release container: {}", e))?;

            println!("✓ Container {} released (unpaused)", container_id);
        }
    }

    Ok(())
}
