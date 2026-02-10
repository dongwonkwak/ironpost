use anyhow::Result;
use std::sync::Arc;

use ironpost_container_guard::{BollardDockerClient, ContainerGuardBuilder};
use ironpost_core::pipeline::Pipeline;
use ironpost_log_pipeline::LogPipelineBuilder;

#[tokio::main]
async fn main() -> Result<()> {
    // 로깅 초기화
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,ironpost=debug".to_owned()),
        )
        .json()
        .init();

    tracing::info!("ironpost-daemon starting");

    // 모듈 간 통신 채널 생성
    let (alert_tx, alert_rx) = tokio::sync::mpsc::channel(256);

    // 로그 파이프라인 빌드
    let (mut log_pipeline, _alert_rx_internal) = LogPipelineBuilder::new()
        .alert_sender(alert_tx)
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build log pipeline: {}", e))?;

    tracing::info!("log pipeline initialized");

    // 컨테이너 가드 빌드
    let docker_client = Arc::new(
        BollardDockerClient::connect_local()
            .map_err(|e| anyhow::anyhow!("failed to create docker client: {}", e))?,
    );

    let (mut container_guard, _action_rx) = ContainerGuardBuilder::new()
        .docker_client(docker_client)
        .alert_receiver(alert_rx)
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build container guard: {}", e))?;

    tracing::info!("container guard initialized");

    // 파이프라인 시작
    log_pipeline
        .start()
        .await
        .map_err(|e| anyhow::anyhow!("failed to start log pipeline: {}", e))?;
    tracing::info!("log pipeline started");

    container_guard
        .start()
        .await
        .map_err(|e| anyhow::anyhow!("failed to start container guard: {}", e))?;
    tracing::info!("container guard started");

    // 종료 시그널 대기
    tracing::info!("ironpost-daemon running — modules active");
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutdown signal received");

    // 우아한 종료
    if let Err(e) = container_guard.stop().await {
        tracing::error!(error = %e, "failed to stop container guard");
    }
    if let Err(e) = log_pipeline.stop().await {
        tracing::error!(error = %e, "failed to stop log pipeline");
    }

    tracing::info!("ironpost-daemon shut down");
    Ok(())
}
