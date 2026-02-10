//! Channel integration tests.
//!
//! Tests inter-module communication via tokio::mpsc channels:
//! - eBPF → Log Pipeline (PacketEvent)
//! - Log Pipeline → Container Guard (AlertEvent)
//! - Container Guard → Logger (ActionEvent)

use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

use ironpost_core::event::{ActionEvent, AlertEvent, EventMetadata, PacketEvent};
use ironpost_core::types::{Alert, PacketInfo, Severity};

#[tokio::test]
async fn test_packet_event_channel_send_receive() {
    // Given: A channel for PacketEvents
    let (tx, mut rx) = mpsc::channel::<PacketEvent>(16);

    // When: Sending a packet event
    let packet = PacketEvent {
        metadata: EventMetadata {
            timestamp: std::time::SystemTime::now(),
            source_module: "ebpf-engine".to_string(),
            trace_id: uuid::Uuid::new_v4().to_string(),
        },
        packet: PacketInfo {
            src_ip: "192.168.1.100".to_string(),
            dst_ip: "10.0.0.1".to_string(),
            src_port: 54321,
            dst_port: 80,
            protocol: "TCP".to_string(),
            action: "allow".to_string(),
        },
    };

    tx.send(packet.clone())
        .await
        .expect("should send packet event");

    // Then: Receiving should succeed
    let received = timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("should not timeout")
        .expect("should receive event");

    assert_eq!(received.packet.src_ip, "192.168.1.100");
    assert_eq!(received.packet.dst_port, 80);
}

#[tokio::test]
async fn test_alert_event_channel_send_receive() {
    // Given: A channel for AlertEvents
    let (tx, mut rx) = mpsc::channel::<AlertEvent>(16);

    // When: Sending an alert event
    let alert = create_test_alert("suspicious-login");

    tx.send(alert.clone()).await.expect("should send alert");

    // Then: Should receive alert
    let received = timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("should not timeout")
        .expect("should receive alert");

    assert_eq!(received.alert.rule_name, "Test Rule");
    assert!(matches!(received.severity, Severity::Medium));
}

#[tokio::test]
async fn test_action_event_channel_send_receive() {
    // Given: A channel for ActionEvents
    let (tx, mut rx) = mpsc::channel::<ActionEvent>(16);

    // When: Sending an action event
    let action = ActionEvent {
        id: uuid::Uuid::new_v4().to_string(),
        metadata: EventMetadata {
            timestamp: std::time::SystemTime::now(),
            source_module: "container-guard".to_string(),
            trace_id: uuid::Uuid::new_v4().to_string(),
        },
        action_type: "isolate".to_string(),
        target: "container-abc123".to_string(),
        success: true,
    };

    tx.send(action.clone()).await.expect("should send action");

    // Then: Should receive action
    let received = timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("should not timeout")
        .expect("should receive action");

    assert_eq!(received.action_type, "isolate");
    assert_eq!(received.target, "container-abc123");
    assert!(received.success);
}

#[tokio::test]
async fn test_channel_back_pressure() {
    // Given: A small-capacity channel
    let (tx, mut rx) = mpsc::channel::<AlertEvent>(2);

    // When: Filling channel beyond capacity (non-blocking sends)
    let alert1 = create_test_alert("alert-1");
    let alert2 = create_test_alert("alert-2");
    let alert3 = create_test_alert("alert-3");

    tx.send(alert1).await.expect("first send should succeed");
    tx.send(alert2).await.expect("second send should succeed");

    // Third send will block until receiver drains
    let send_task = tokio::spawn(async move {
        tx.send(alert3).await.expect("third send should succeed after drain");
    });

    // Drain one message
    rx.recv().await.expect("should receive first message");

    // Then: Third send should now succeed
    timeout(Duration::from_secs(1), send_task)
        .await
        .expect("send should complete after drain")
        .expect("task should succeed");
}

#[tokio::test]
async fn test_channel_close_on_sender_drop() {
    // Given: A channel with sender
    let (tx, mut rx) = mpsc::channel::<PacketEvent>(16);

    // When: Dropping sender
    drop(tx);

    // Then: Receiver should return None
    let result = rx.recv().await;
    assert!(result.is_none(), "receive should return None after sender dropped");
}

#[tokio::test]
async fn test_channel_multiple_senders() {
    // Given: Multiple senders to same channel
    let (tx, mut rx) = mpsc::channel::<AlertEvent>(16);
    let tx2 = tx.clone();
    let tx3 = tx.clone();

    // When: Sending from multiple senders
    let alert1 = create_test_alert("alert-1");
    let alert2 = create_test_alert("alert-2");
    let alert3 = create_test_alert("alert-3");

    tx.send(alert1).await.expect("tx1 should send");
    tx2.send(alert2).await.expect("tx2 should send");
    tx3.send(alert3).await.expect("tx3 should send");

    // Then: All messages should be received
    let mut received_ids = Vec::new();
    for _ in 0..3 {
        let alert = rx.recv().await.expect("should receive alert");
        received_ids.push(alert.id.clone());
    }

    assert_eq!(received_ids.len(), 3, "should receive all 3 alerts");
}

#[tokio::test]
async fn test_channel_try_send_when_full() {
    // Given: A full channel
    let (tx, _rx) = mpsc::channel::<AlertEvent>(1);
    let alert1 = create_test_alert("alert-1");
    let alert2 = create_test_alert("alert-2");

    tx.send(alert1).await.expect("first send should succeed");

    // When: Trying to send when full
    let result = tx.try_send(alert2);

    // Then: Should fail with Full error
    assert!(result.is_err(), "try_send should fail when channel is full");
}

#[tokio::test]
async fn test_channel_receiver_closes_gracefully() {
    // Given: A channel with pending messages
    let (tx, mut rx) = mpsc::channel::<PacketEvent>(16);

    let packet = PacketEvent {
        metadata: EventMetadata {
            timestamp: std::time::SystemTime::now(),
            source_module: "test".to_string(),
            trace_id: uuid::Uuid::new_v4().to_string(),
        },
        packet: PacketInfo {
            src_ip: "1.2.3.4".to_string(),
            dst_ip: "5.6.7.8".to_string(),
            src_port: 1234,
            dst_port: 80,
            protocol: "TCP".to_string(),
            action: "allow".to_string(),
        },
    };

    tx.send(packet).await.expect("should send");

    // When: Closing receiver
    rx.close();

    // Then: Should still drain remaining messages
    let result = rx.recv().await;
    assert!(result.is_some(), "should drain pending message");

    // Next recv should return None
    let result2 = rx.recv().await;
    assert!(result2.is_none(), "should return None after drain");
}

#[tokio::test]
async fn test_channel_send_timeout() {
    // Given: A full channel with no receiver draining
    let (tx, _rx) = mpsc::channel::<AlertEvent>(1);
    let alert1 = create_test_alert("alert-1");
    let alert2 = create_test_alert("alert-2");

    tx.send(alert1).await.expect("first send should succeed");

    // When: Attempting to send with timeout
    let send_future = tx.send(alert2);
    let result = timeout(Duration::from_millis(100), send_future).await;

    // Then: Should timeout
    assert!(result.is_err(), "send should timeout when channel is full");
}

#[tokio::test]
async fn test_channel_empty_receive_timeout() {
    // Given: An empty channel
    let (_tx, mut rx) = mpsc::channel::<PacketEvent>(16);

    // When: Attempting to receive with timeout
    let result = timeout(Duration::from_millis(100), rx.recv()).await;

    // Then: Should timeout
    assert!(result.is_err(), "receive should timeout when channel is empty");
}

#[tokio::test]
async fn test_channel_large_message_batch() {
    // Given: A channel and many messages
    let (tx, mut rx) = mpsc::channel::<AlertEvent>(100);
    let count = 50;

    // When: Sending many messages
    for i in 0..count {
        let alert = create_test_alert(&format!("alert-{}", i));
        tx.send(alert).await.expect("should send alert");
    }

    drop(tx); // Close sender

    // Then: All messages should be received
    let mut received_count = 0;
    while let Some(_alert) = rx.recv().await {
        received_count += 1;
    }

    assert_eq!(received_count, count, "should receive all alerts");
}

#[tokio::test]
async fn test_channel_unicode_in_messages() {
    // Given: A channel for alerts
    let (tx, mut rx) = mpsc::channel::<AlertEvent>(16);

    // When: Sending alert with unicode content
    let mut alert = create_test_alert("unicode-test");
    alert.alert.title = "의심스러운 활동 감지".to_string();
    alert.alert.description = "비정상적인 접근 패턴".to_string();

    tx.send(alert).await.expect("should send unicode alert");

    // Then: Should receive with unicode preserved
    let received = rx.recv().await.expect("should receive alert");
    assert!(received.alert.title.contains("의심스러운"));
    assert!(received.alert.description.contains("비정상적인"));
}

#[tokio::test]
async fn test_channel_zero_capacity_rendezvous() {
    // Given: A zero-capacity channel (rendezvous)
    let (tx, mut rx) = mpsc::channel::<ActionEvent>(0);

    // When: Spawning receiver task
    let recv_task = tokio::spawn(async move {
        rx.recv().await.expect("should receive action")
    });

    // Give receiver time to start waiting
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Send action (will block until receiver is ready)
    let action = ActionEvent {
        id: uuid::Uuid::new_v4().to_string(),
        metadata: EventMetadata {
            timestamp: std::time::SystemTime::now(),
            source_module: "test".to_string(),
            trace_id: uuid::Uuid::new_v4().to_string(),
        },
        action_type: "test".to_string(),
        target: "target".to_string(),
        success: true,
    };

    tx.send(action.clone()).await.expect("should send");

    // Then: Receiver should get the message
    let received = recv_task.await.expect("recv task should complete");
    assert_eq!(received.action_type, "test");
}

// Helper function to create test alerts
fn create_test_alert(rule_name: &str) -> AlertEvent {
    let alert = Alert {
        id: uuid::Uuid::new_v4().to_string(),
        title: rule_name.to_string(),
        description: "Test alert".to_string(),
        severity: Severity::Medium,
        rule_name: "Test Rule".to_string(),
        source_ip: None,
        target_ip: None,
        timestamp: std::time::SystemTime::now(),
    };

    AlertEvent {
        id: uuid::Uuid::new_v4().to_string(),
        metadata: EventMetadata {
            timestamp: std::time::SystemTime::now(),
            source_module: "test".to_string(),
            trace_id: uuid::Uuid::new_v4().to_string(),
        },
        alert,
        severity: Severity::Medium,
    }
}
