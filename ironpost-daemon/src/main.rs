use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // 로깅 초기화
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .json()
        .init();

    tracing::info!("ironpost-daemon starting");

    // TODO: 설정 로드
    // let config = load_config("ironpost.toml").await?;

    // TODO: 이벤트 버스 생성 (모듈 간 통신 채널)
    // let (event_tx, event_rx) = tokio::sync::mpsc::channel(1024);
    // let (alert_tx, alert_rx) = tokio::sync::mpsc::channel(256);

    // TODO: 모듈 초기화
    // let ebpf_engine = EbpfEngine::new(config.ebpf, event_tx.clone()).await?;
    // let log_pipeline = LogPipeline::new(config.log_pipeline, event_rx, alert_tx).await?;
    // let container_guard = ContainerGuard::new(config.container, alert_rx).await?;
    // let sbom_scanner = SbomScanner::new(config.sbom).await?;

    // TODO: 모듈 실행
    // tokio::select! {
    //     result = ebpf_engine.run() => { result?; }
    //     result = log_pipeline.run() => { result?; }
    //     result = container_guard.run() => { result?; }
    //     _ = tokio::signal::ctrl_c() => {
    //         tracing::info!("shutdown signal received");
    //     }
    // }

    // Placeholder: 시그널 대기
    tracing::info!("ironpost-daemon running (placeholder — modules not yet wired)");
    tokio::signal::ctrl_c().await?;
    tracing::info!("ironpost-daemon shutting down");

    Ok(())
}
