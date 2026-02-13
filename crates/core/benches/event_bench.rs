//! 이벤트 시스템 벤치마크
//!
//! Event 생성, 직렬화, 채널 통신 성능을 측정합니다.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ironpost_core::event::{AlertEvent, LogEvent, PacketEvent, ActionEvent, EventMetadata};
use ironpost_core::types::{Alert, LogEntry, PacketInfo, Severity};
use bytes::Bytes;
use std::net::IpAddr;
use std::time::SystemTime;

fn create_packet_info() -> PacketInfo {
    PacketInfo {
        src_ip: "192.168.1.100".parse::<IpAddr>().unwrap(),
        dst_ip: "10.0.0.1".parse::<IpAddr>().unwrap(),
        src_port: 12345,
        dst_port: 80,
        protocol: 6,
        size: 1500,
        timestamp: SystemTime::now(),
    }
}

fn create_log_entry() -> LogEntry {
    LogEntry {
        source: "/var/log/syslog".to_owned(),
        timestamp: SystemTime::now(),
        hostname: "web-server-01".to_owned(),
        process: "nginx".to_owned(),
        message: "GET /api/v1/users HTTP/1.1 200 OK".to_owned(),
        severity: Severity::Info,
        fields: vec![
            ("request_id".to_owned(), "550e8400-e29b-41d4-a716-446655440000".to_owned()),
            ("duration_ms".to_owned(), "125".to_owned()),
            ("status".to_owned(), "200".to_owned()),
        ],
    }
}

fn create_alert() -> Alert {
    Alert {
        id: "alert-001".to_owned(),
        title: "SSH Brute Force Detected".to_owned(),
        description: "Multiple failed SSH login attempts from 192.168.1.100".to_owned(),
        severity: Severity::High,
        rule_name: "ssh_brute_force".to_owned(),
        source_ip: Some("192.168.1.100".parse().unwrap()),
        target_ip: Some("10.0.0.1".parse().unwrap()),
        created_at: SystemTime::now(),
    }
}

fn bench_event_creation(c: &mut Criterion) {
    let packet_info = create_packet_info();
    let raw_data = Bytes::from_static(b"raw packet data payload");
    let log_entry = create_log_entry();
    let alert = create_alert();

    let mut group = c.benchmark_group("event_creation");
    group.throughput(Throughput::Elements(1));

    group.bench_function("packet_event_new", |b| {
        b.iter(|| {
            PacketEvent::new(black_box(packet_info.clone()), black_box(raw_data.clone()))
        })
    });

    group.bench_function("packet_event_with_trace", |b| {
        b.iter(|| {
            PacketEvent::with_trace(
                black_box(packet_info.clone()),
                black_box(raw_data.clone()),
                black_box("trace-id-12345"),
            )
        })
    });

    group.bench_function("log_event_new", |b| {
        b.iter(|| {
            LogEvent::new(black_box(log_entry.clone()))
        })
    });

    group.bench_function("alert_event_new", |b| {
        b.iter(|| {
            AlertEvent::new(black_box(alert.clone()), black_box(Severity::High))
        })
    });

    group.bench_function("action_event_new", |b| {
        b.iter(|| {
            ActionEvent::new(
                black_box("container_pause"),
                black_box("container-abc123"),
                black_box(true),
            )
        })
    });

    group.finish();
}

fn bench_event_metadata(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_metadata");
    group.throughput(Throughput::Elements(1));

    group.bench_function("metadata_new", |b| {
        b.iter(|| {
            EventMetadata::new(black_box("test-module"), black_box("trace-12345"))
        })
    });

    group.bench_function("metadata_with_new_trace", |b| {
        b.iter(|| {
            EventMetadata::with_new_trace(black_box("test-module"))
        })
    });

    group.bench_function("metadata_display", |b| {
        let meta = EventMetadata::new("test-module", "trace-12345");
        b.iter(|| {
            let _s = format!("{}", black_box(&meta));
        })
    });

    group.finish();
}

fn bench_event_serialization(c: &mut Criterion) {
    let packet_event = PacketEvent::new(create_packet_info(), Bytes::from_static(b"data"));
    let log_entry = create_log_entry();
    let alert = create_alert();

    let mut group = c.benchmark_group("event_serialization");
    group.throughput(Throughput::Elements(1));

    // LogEntry 직렬화 (serde를 통한)
    group.bench_function("log_entry_to_json", |b| {
        b.iter(|| {
            serde_json::to_string(black_box(&log_entry)).unwrap()
        })
    });

    // Alert 직렬화
    group.bench_function("alert_to_json", |b| {
        b.iter(|| {
            serde_json::to_string(black_box(&alert)).unwrap()
        })
    });

    // PacketInfo 직렬화
    group.bench_function("packet_info_to_json", |b| {
        b.iter(|| {
            serde_json::to_string(black_box(&packet_event.packet_info)).unwrap()
        })
    });

    group.finish();
}

fn bench_event_cloning(c: &mut Criterion) {
    let packet_event = PacketEvent::new(create_packet_info(), Bytes::from_static(b"data payload"));
    let log_event = LogEvent::new(create_log_entry());
    let alert_event = AlertEvent::new(create_alert(), Severity::High);
    let action_event = ActionEvent::new("pause", "container-id", true);

    let mut group = c.benchmark_group("event_cloning");
    group.throughput(Throughput::Elements(1));

    group.bench_function("packet_event_clone", |b| {
        b.iter(|| {
            let _ = black_box(&packet_event).clone();
        })
    });

    group.bench_function("log_event_clone", |b| {
        b.iter(|| {
            let _ = black_box(&log_event).clone();
        })
    });

    group.bench_function("alert_event_clone", |b| {
        b.iter(|| {
            let _ = black_box(&alert_event).clone();
        })
    });

    group.bench_function("action_event_clone", |b| {
        b.iter(|| {
            let _ = black_box(&action_event).clone();
        })
    });

    group.finish();
}

fn bench_channel_throughput(c: &mut Criterion) {
    use tokio::runtime::Runtime;

    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("channel_throughput");

    // 작은 배치 (100개)
    group.throughput(Throughput::Elements(100));
    group.bench_function("send_recv_100_events", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (tx, mut rx) = tokio::sync::mpsc::channel::<LogEvent>(100);

                let sender = tokio::spawn(async move {
                    for _ in 0..100 {
                        let event = LogEvent::new(create_log_entry());
                        tx.send(event).await.unwrap();
                    }
                });

                let receiver = tokio::spawn(async move {
                    let mut count = 0;
                    while let Some(_event) = rx.recv().await {
                        count += 1;
                        if count >= 100 {
                            break;
                        }
                    }
                });

                sender.await.unwrap();
                receiver.await.unwrap();
            })
        })
    });

    // 큰 배치 (1000개)
    group.throughput(Throughput::Elements(1000));
    group.bench_function("send_recv_1000_events", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (tx, mut rx) = tokio::sync::mpsc::channel::<LogEvent>(1000);

                let sender = tokio::spawn(async move {
                    for _ in 0..1000 {
                        let event = LogEvent::new(create_log_entry());
                        tx.send(event).await.unwrap();
                    }
                });

                let receiver = tokio::spawn(async move {
                    let mut count = 0;
                    while let Some(_event) = rx.recv().await {
                        count += 1;
                        if count >= 1000 {
                            break;
                        }
                    }
                });

                sender.await.unwrap();
                receiver.await.unwrap();
            })
        })
    });

    group.finish();
}

fn bench_event_display(c: &mut Criterion) {
    let packet_event = PacketEvent::new(create_packet_info(), Bytes::from_static(b"data"));
    let log_event = LogEvent::new(create_log_entry());
    let alert_event = AlertEvent::new(create_alert(), Severity::High);
    let action_event = ActionEvent::new("pause", "container-id", true);

    let mut group = c.benchmark_group("event_display");
    group.throughput(Throughput::Elements(1));

    group.bench_function("packet_event_display", |b| {
        b.iter(|| {
            let _s = format!("{}", black_box(&packet_event));
        })
    });

    group.bench_function("log_event_display", |b| {
        b.iter(|| {
            let _s = format!("{}", black_box(&log_event));
        })
    });

    group.bench_function("alert_event_display", |b| {
        b.iter(|| {
            let _s = format!("{}", black_box(&alert_event));
        })
    });

    group.bench_function("action_event_display", |b| {
        b.iter(|| {
            let _s = format!("{}", black_box(&action_event));
        })
    });

    group.finish();
}

fn bench_event_type_polymorphism(c: &mut Criterion) {
    use ironpost_core::event::Event;

    let packet_event = PacketEvent::new(create_packet_info(), Bytes::from_static(b"data"));
    let log_event = LogEvent::new(create_log_entry());
    let alert_event = AlertEvent::new(create_alert(), Severity::High);

    let mut group = c.benchmark_group("event_trait_methods");
    group.throughput(Throughput::Elements(1));

    group.bench_function("packet_event_id", |b| {
        b.iter(|| {
            let _id = black_box(&packet_event).event_id();
        })
    });

    group.bench_function("log_event_metadata", |b| {
        b.iter(|| {
            let _meta = black_box(&log_event).metadata();
        })
    });

    group.bench_function("alert_event_type", |b| {
        b.iter(|| {
            let _type = black_box(&alert_event).event_type();
        })
    });

    group.finish();
}

fn bench_log_entry_field_variations(c: &mut Criterion) {
    let mut group = c.benchmark_group("log_entry_fields");

    // 필드 없음
    let no_fields = LogEntry {
        source: "syslog".to_owned(),
        timestamp: SystemTime::now(),
        hostname: "host".to_owned(),
        process: "proc".to_owned(),
        message: "msg".to_owned(),
        severity: Severity::Info,
        fields: vec![],
    };

    // 필드 10개
    let many_fields = LogEntry {
        source: "syslog".to_owned(),
        timestamp: SystemTime::now(),
        hostname: "host".to_owned(),
        process: "proc".to_owned(),
        message: "msg".to_owned(),
        severity: Severity::Info,
        fields: (0..10)
            .map(|i| (format!("field_{}", i), format!("value_{}", i)))
            .collect(),
    };

    group.bench_function("serialize_no_fields", |b| {
        b.iter(|| {
            serde_json::to_string(black_box(&no_fields)).unwrap()
        })
    });

    group.bench_function("serialize_10_fields", |b| {
        b.iter(|| {
            serde_json::to_string(black_box(&many_fields)).unwrap()
        })
    });

    group.bench_function("clone_no_fields", |b| {
        b.iter(|| {
            let _ = black_box(&no_fields).clone();
        })
    });

    group.bench_function("clone_10_fields", |b| {
        b.iter(|| {
            let _ = black_box(&many_fields).clone();
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_event_creation,
    bench_event_metadata,
    bench_event_serialization,
    bench_event_cloning,
    bench_channel_throughput,
    bench_event_display,
    bench_event_type_polymorphism,
    bench_log_entry_field_variations
);
criterion_main!(benches);
