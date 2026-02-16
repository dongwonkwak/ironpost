//! eBPF 이벤트 수신기
//!
//! `ironpost-daemon`에서 조립한 `tokio::mpsc` 채널을 통해
//! eBPF 엔진의 [`PacketEvent`]를 수신하고,
//! 로그 파이프라인에서 처리할 수 있는 [`RawLog`] 형태로 변환합니다.
//!
//! # 아키텍처 원칙
//! log-pipeline은 ebpf-engine에 직접 의존하지 않습니다.
//! `ironpost-daemon`이 채널을 생성하여 양 모듈을 연결합니다.

use ironpost_core::event::PacketEvent;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::{CollectorStatus, RawLog};
use crate::error::LogPipelineError;

/// eBPF 이벤트 수신기
///
/// `PacketEvent`를 `RawLog`로 변환하여 파이프라인에 주입합니다.
/// 이벤트의 패킷 정보를 JSON 형식으로 직렬화하여 로그 파서가
/// 처리할 수 있도록 합니다.
#[allow(dead_code)]
pub struct EventReceiver {
    /// PacketEvent 수신 채널
    #[allow(dead_code)]
    packet_rx: mpsc::Receiver<PacketEvent>,
    /// 변환된 RawLog 전송 채널
    #[allow(dead_code)]
    tx: mpsc::Sender<RawLog>,
    /// 현재 상태
    status: CollectorStatus,
    /// 수신한 이벤트 카운터
    received_count: u64,
}

#[allow(dead_code)]
impl EventReceiver {
    /// 새 이벤트 수신기를 생성합니다.
    ///
    /// # Arguments
    /// - `packet_rx`: `ironpost-daemon`에서 전달받은 PacketEvent 수신 채널
    /// - `tx`: 파이프라인 내부의 RawLog 전송 채널
    pub fn new(packet_rx: mpsc::Receiver<PacketEvent>, tx: mpsc::Sender<RawLog>) -> Self {
        Self {
            packet_rx,
            tx,
            status: CollectorStatus::Idle,
            received_count: 0,
        }
    }

    /// 수신기를 시작합니다.
    ///
    /// PacketEvent를 수신하여 RawLog로 변환한 뒤 파이프라인으로 전달합니다.
    /// 송신 측 채널이 닫히거나 cancellation token이 발동되면 자동 종료되고
    /// packet_rx를 반환하여 재시작을 지원합니다.
    pub async fn run(
        mut self,
        cancel: CancellationToken,
    ) -> Result<mpsc::Receiver<PacketEvent>, LogPipelineError> {
        use tracing::{debug, error, info};

        self.status = CollectorStatus::Running;
        info!("Starting event receiver from ebpf-engine");

        loop {
            tokio::select! {
                result = self.packet_rx.recv() => {
                    match result {
                        Some(event) => {
                            debug!("Received PacketEvent: {:?}", event.packet_info);

                            // PacketEvent를 RawLog로 변환
                            let raw_log = Self::packet_event_to_raw_log(&event)?;

                            // 파이프라인으로 전송
                            if let Err(e) = self.tx.send(raw_log).await {
                                error!("Failed to send RawLog to pipeline: {}", e);
                                self.status = CollectorStatus::Error(e.to_string());
                                return Err(LogPipelineError::Channel(e.to_string()));
                            }

                            self.received_count += 1;
                        }
                        None => {
                            // 송신 측 채널이 닫힘 - 정상 종료
                            info!("PacketEvent channel closed, shutting down event receiver");
                            self.status = CollectorStatus::Stopped;
                            break;
                        }
                    }
                }
                _ = cancel.cancelled() => {
                    info!("Event receiver received shutdown signal");
                    self.status = CollectorStatus::Stopped;
                    break;
                }
            }
        }

        Ok(self.packet_rx)
    }

    /// PacketEvent를 RawLog로 변환합니다.
    ///
    /// 패킷 정보를 JSON으로 직렬화하여 일반 로그 파서가 처리할 수 있도록 합니다.
    /// trace_id를 보존하여 이벤트 추적 연속성을 유지합니다.
    fn packet_event_to_raw_log(event: &PacketEvent) -> Result<RawLog, LogPipelineError> {
        let json = serde_json::json!({
            "source": "ebpf",
            "event_type": "packet",
            "trace_id": event.metadata.trace_id,
            "src_ip": event.packet_info.src_ip.to_string(),
            "dst_ip": event.packet_info.dst_ip.to_string(),
            "src_port": event.packet_info.src_port,
            "dst_port": event.packet_info.dst_port,
            "protocol": event.packet_info.protocol,
            "size": event.packet_info.size,
            "message": format!(
                "packet {}:{} -> {}:{}",
                event.packet_info.src_ip,
                event.packet_info.src_port,
                event.packet_info.dst_ip,
                event.packet_info.dst_port,
            ),
        });

        let data = serde_json::to_vec(&json).map_err(|e| LogPipelineError::Collector {
            source_type: "event_receiver".to_owned(),
            reason: format!("failed to serialize PacketEvent: {e}"),
        })?;

        Ok(RawLog::new(bytes::Bytes::from(data), "ebpf-engine").with_format_hint("json"))
    }

    /// 수신한 이벤트 수를 반환합니다.
    pub fn received_count(&self) -> u64 {
        self.received_count
    }

    /// 현재 상태를 반환합니다.
    pub fn status(&self) -> &CollectorStatus {
        &self.status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironpost_core::types::PacketInfo;
    use std::time::SystemTime;

    fn sample_packet_event() -> PacketEvent {
        PacketEvent::new(
            PacketInfo {
                src_ip: "192.168.1.1".parse().unwrap(),
                dst_ip: "10.0.0.1".parse().unwrap(),
                src_port: 12345,
                dst_port: 80,
                protocol: 6,
                size: 1500,
                timestamp: SystemTime::now(),
            },
            bytes::Bytes::from_static(b"packet-data"),
        )
    }

    #[test]
    fn packet_event_to_raw_log_produces_json() {
        let event = sample_packet_event();
        let raw = EventReceiver::packet_event_to_raw_log(&event).unwrap();
        assert_eq!(raw.source, "ebpf-engine");
        assert_eq!(raw.format_hint, Some("json".to_owned()));

        // JSON 파싱 가능한지 확인
        let value: serde_json::Value = serde_json::from_slice(&raw.data).unwrap();
        assert_eq!(value["src_ip"], "192.168.1.1");
        assert_eq!(value["dst_port"], 80);
        assert_eq!(value["protocol"], 6);
    }

    #[test]
    fn receiver_starts_idle() {
        let (_packet_tx, packet_rx) = mpsc::channel(10);
        let (tx, _rx) = mpsc::channel(10);
        let receiver = EventReceiver::new(packet_rx, tx);
        assert_eq!(*receiver.status(), CollectorStatus::Idle);
        assert_eq!(receiver.received_count(), 0);
    }

    #[tokio::test]
    async fn receive_and_convert_packet_event() {
        let (packet_tx, packet_rx) = mpsc::channel(10);
        let (tx, mut rx) = mpsc::channel(10);

        let receiver = EventReceiver::new(packet_rx, tx);
        let cancel = CancellationToken::new();

        // 이벤트를 백그라운드 태스크로 수신
        let handle = tokio::spawn(async move { receiver.run(cancel).await });

        // 테스트 이벤트 전송
        let event = sample_packet_event();
        packet_tx.send(event).await.unwrap();

        // RawLog 수신 확인
        let raw_log = tokio::time::timeout(tokio::time::Duration::from_millis(100), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(raw_log.source, "ebpf-engine");
        assert_eq!(raw_log.format_hint, Some("json".to_owned()));

        // JSON 파싱 확인
        let value: serde_json::Value = serde_json::from_slice(&raw_log.data).unwrap();
        assert_eq!(value["src_ip"], "192.168.1.1");

        // 채널 닫기로 종료
        drop(packet_tx);
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn receiver_stops_when_channel_closed() {
        let packet_rx = {
            let (packet_tx, packet_rx) = mpsc::channel(10);
            drop(packet_tx); // 명시적으로 송신 측 닫기
            packet_rx
        };
        let (tx, _rx) = mpsc::channel(10);

        let receiver = EventReceiver::new(packet_rx, tx);
        let cancel = CancellationToken::new();

        // 송신 측 채널이 이미 닫혔으므로 즉시 종료되어야 함
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), receiver.run(cancel)).await;

        assert!(result.is_ok(), "Test timed out");
        let returned_rx = result.unwrap();
        assert!(returned_rx.is_ok());
    }

    #[test]
    fn json_contains_all_packet_fields() {
        let event = sample_packet_event();
        let raw = EventReceiver::packet_event_to_raw_log(&event).unwrap();

        let value: serde_json::Value = serde_json::from_slice(&raw.data).unwrap();

        // 필수 필드 확인
        assert!(value.get("source").is_some());
        assert!(value.get("event_type").is_some());
        assert!(value.get("trace_id").is_some());
        assert!(value.get("src_ip").is_some());
        assert!(value.get("dst_ip").is_some());
        assert!(value.get("src_port").is_some());
        assert!(value.get("dst_port").is_some());
        assert!(value.get("protocol").is_some());
        assert!(value.get("size").is_some());
        assert!(value.get("message").is_some());

        // 값 타입 확인
        assert!(value["src_ip"].is_string());
        assert!(value["src_port"].is_number());
        assert!(value["protocol"].is_number());
    }
}
