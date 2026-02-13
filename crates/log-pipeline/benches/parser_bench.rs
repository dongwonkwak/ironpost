//! 로그 파서 벤치마크
//!
//! Syslog RFC5424, RFC3164, JSON 파서의 처리량을 측정합니다.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ironpost_core::pipeline::LogParser;
use ironpost_log_pipeline::parser::{JsonLogParser, SyslogParser};

/// Syslog RFC5424 짧은 메시지 (structured data 없음)
const SYSLOG_5424_SHORT: &[u8] =
    b"<34>1 2024-01-15T12:00:00Z myhost sshd 1234 - - Failed password for root";

/// Syslog RFC5424 긴 메시지 (structured data 포함)
const SYSLOG_5424_LONG: &[u8] = b"<34>1 2024-01-15T12:00:00.123456Z web-server-01 nginx 5678 ID123 [request user=\"admin\" path=\"/api/v1/users\" method=\"POST\" status=\"403\"][performance time=\"125ms\" cpu=\"45%\"] Unauthorized API access attempt from 192.168.1.100 to restricted endpoint /api/v1/users with invalid token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

/// Syslog RFC3164 짧은 메시지
const SYSLOG_3164_SHORT: &[u8] = b"<34>Jan 15 12:00:00 myhost sshd: Failed password for root";

/// Syslog RFC3164 긴 메시지
const SYSLOG_3164_LONG: &[u8] = b"<34>Dec 31 23:59:59 production-server-eu-west-1a authentication-service[12345]: Authentication failure for user admin@example.com from IP address 203.0.113.45 using password authentication method after 3 previous attempts within 60 seconds exceeding rate limit threshold";

/// JSON 짧은 메시지
const JSON_SHORT: &[u8] = br#"{"timestamp":"2024-01-15T12:00:00Z","host":"web-01","process":"nginx","message":"request processed","level":"info"}"#;

/// JSON 긴 메시지 (중첩 객체 포함)
const JSON_LONG: &[u8] = br#"{"timestamp":"2024-01-15T12:00:00.123456Z","host":"production-web-server-01","process":"api-gateway","message":"API request completed successfully","level":"info","request_id":"550e8400-e29b-41d4-a716-446655440000","duration_ms":245,"http":{"method":"POST","path":"/api/v1/users/create","status":201,"user_agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},"metadata":{"region":"us-east-1","environment":"production","version":"2.5.1"},"custom_field_1":"value1","custom_field_2":"value2","custom_field_3":"value3"}"#;

fn bench_syslog_rfc5424(c: &mut Criterion) {
    let parser = SyslogParser::new();

    let mut group = c.benchmark_group("syslog_rfc5424");

    // 짧은 메시지
    group.throughput(Throughput::Elements(1));
    group.bench_function("short", |b| {
        b.iter(|| {
            parser.parse(black_box(SYSLOG_5424_SHORT)).unwrap()
        })
    });

    // 긴 메시지
    group.bench_function("long_with_structured_data", |b| {
        b.iter(|| {
            parser.parse(black_box(SYSLOG_5424_LONG)).unwrap()
        })
    });

    // 1000건 반복 처리량
    group.throughput(Throughput::Elements(1000));
    group.bench_function("throughput_1000", |b| {
        b.iter(|| {
            for _ in 0..1000 {
                parser.parse(black_box(SYSLOG_5424_SHORT)).unwrap();
            }
        })
    });

    group.finish();
}

fn bench_syslog_rfc3164(c: &mut Criterion) {
    let parser = SyslogParser::new();

    let mut group = c.benchmark_group("syslog_rfc3164");

    // 짧은 메시지
    group.throughput(Throughput::Elements(1));
    group.bench_function("short", |b| {
        b.iter(|| {
            parser.parse(black_box(SYSLOG_3164_SHORT)).unwrap()
        })
    });

    // 긴 메시지
    group.bench_function("long", |b| {
        b.iter(|| {
            parser.parse(black_box(SYSLOG_3164_LONG)).unwrap()
        })
    });

    // 1000건 반복 처리량
    group.throughput(Throughput::Elements(1000));
    group.bench_function("throughput_1000", |b| {
        b.iter(|| {
            for _ in 0..1000 {
                parser.parse(black_box(SYSLOG_3164_SHORT)).unwrap();
            }
        })
    });

    group.finish();
}

fn bench_json_parser(c: &mut Criterion) {
    let parser = JsonLogParser::default();

    let mut group = c.benchmark_group("json_parser");

    // 짧은 메시지
    group.throughput(Throughput::Elements(1));
    group.bench_function("short", |b| {
        b.iter(|| {
            parser.parse(black_box(JSON_SHORT)).unwrap()
        })
    });

    // 긴 메시지 (중첩 객체)
    group.bench_function("long_nested", |b| {
        b.iter(|| {
            parser.parse(black_box(JSON_LONG)).unwrap()
        })
    });

    // 1000건 반복 처리량
    group.throughput(Throughput::Elements(1000));
    group.bench_function("throughput_1000", |b| {
        b.iter(|| {
            for _ in 0..1000 {
                parser.parse(black_box(JSON_SHORT)).unwrap();
            }
        })
    });

    group.finish();
}

fn bench_parser_comparison(c: &mut Criterion) {
    let syslog_parser = SyslogParser::new();
    let json_parser = JsonLogParser::default();

    let mut group = c.benchmark_group("parser_comparison");
    group.throughput(Throughput::Elements(1000));

    group.bench_with_input(
        BenchmarkId::new("format", "syslog_rfc5424"),
        &SYSLOG_5424_SHORT,
        |b, &input| {
            b.iter(|| {
                for _ in 0..1000 {
                    syslog_parser.parse(black_box(input)).unwrap();
                }
            })
        },
    );

    group.bench_with_input(
        BenchmarkId::new("format", "syslog_rfc3164"),
        &SYSLOG_3164_SHORT,
        |b, &input| {
            b.iter(|| {
                for _ in 0..1000 {
                    syslog_parser.parse(black_box(input)).unwrap();
                }
            })
        },
    );

    group.bench_with_input(
        BenchmarkId::new("format", "json"),
        &JSON_SHORT,
        |b, &input| {
            b.iter(|| {
                for _ in 0..1000 {
                    json_parser.parse(black_box(input)).unwrap();
                }
            })
        },
    );

    group.finish();
}

criterion_group!(
    benches,
    bench_syslog_rfc5424,
    bench_syslog_rfc3164,
    bench_json_parser,
    bench_parser_comparison
);
criterion_main!(benches);
