//! 로그 버퍼링 -- 인메모리 버퍼 및 배치 플러시
//!
//! [`LogBuffer`]는 수집된 원시 로그를 인메모리에 버퍼링하고,
//! 배치 크기 또는 시간 간격에 따라 플러시합니다.
//!
//! # 오버플로우 정책
//! 버퍼가 가득 찬 경우:
//! - [`DropPolicy::Oldest`](crate::config::DropPolicy::Oldest): 가장 오래된 엔트리를 드롭
//! - [`DropPolicy::Newest`](crate::config::DropPolicy::Newest): 새 유입을 거부

use std::collections::VecDeque;

use crate::collector::RawLog;
use crate::config::DropPolicy;

/// 인메모리 로그 버퍼
///
/// 수집된 원시 로그를 임시 저장하고, 배치 단위로 파서에 전달합니다.
/// 버퍼 용량이 초과되면 설정된 드롭 정책에 따라 엔트리를 제거합니다.
pub struct LogBuffer {
    /// 버퍼 내부 저장소
    buffer: VecDeque<RawLog>,
    /// 최대 용량
    capacity: usize,
    /// 드롭 정책
    drop_policy: DropPolicy,
    /// 드롭된 엔트리 카운터 (통계용)
    dropped_count: u64,
    /// 총 유입 엔트리 카운터
    total_received: u64,
}

impl LogBuffer {
    /// 새 로그 버퍼를 생성합니다.
    pub fn new(capacity: usize, drop_policy: DropPolicy) -> Self {
        Self {
            buffer: VecDeque::with_capacity(capacity.min(10_000)),
            capacity,
            drop_policy,
            dropped_count: 0,
            total_received: 0,
        }
    }

    /// 로그를 버퍼에 추가합니다.
    ///
    /// 버퍼가 가득 찬 경우 드롭 정책에 따라 처리합니다.
    /// 드롭이 발생하면 `true`를 반환합니다.
    pub fn push(&mut self, raw_log: RawLog) -> bool {
        self.total_received += 1;

        if self.buffer.len() >= self.capacity {
            match self.drop_policy {
                DropPolicy::Oldest => {
                    self.buffer.pop_front();
                    self.dropped_count += 1;
                    tracing::warn!(
                        dropped = self.dropped_count,
                        capacity = self.capacity,
                        "buffer full, dropped oldest entry"
                    );
                    self.buffer.push_back(raw_log);
                    return true;
                }
                DropPolicy::Newest => {
                    self.dropped_count += 1;
                    tracing::warn!(
                        dropped = self.dropped_count,
                        capacity = self.capacity,
                        "buffer full, rejected new entry"
                    );
                    return true;
                }
            }
        }

        self.buffer.push_back(raw_log);
        false
    }

    /// 배치 크기만큼 또는 버퍼에 남은 만큼 엔트리를 드레인합니다.
    ///
    /// 버퍼가 비어있으면 빈 Vec을 반환합니다.
    pub fn drain_batch(&mut self, batch_size: usize) -> Vec<RawLog> {
        let count = batch_size.min(self.buffer.len());
        self.buffer.drain(..count).collect()
    }

    /// 버퍼의 모든 엔트리를 드레인합니다.
    pub fn drain_all(&mut self) -> Vec<RawLog> {
        self.buffer.drain(..).collect()
    }

    /// 현재 버퍼에 저장된 엔트리 수를 반환합니다.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// 버퍼가 비어있는지 확인합니다.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// 버퍼 최대 용량을 반환합니다.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// 지금까지 드롭된 엔트리 수를 반환합니다.
    pub fn dropped_count(&self) -> u64 {
        self.dropped_count
    }

    /// 총 유입 엔트리 수를 반환합니다.
    pub fn total_received(&self) -> u64 {
        self.total_received
    }

    /// 버퍼 사용률을 0.0~1.0 범위로 반환합니다.
    pub fn utilization(&self) -> f64 {
        if self.capacity == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.buffer.len()).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.capacity).unwrap_or(u32::MAX))
    }

    /// 배치 플러시 조건을 확인합니다.
    ///
    /// 버퍼에 `batch_size` 이상의 엔트리가 있으면 `true`를 반환합니다.
    pub fn should_flush(&self, batch_size: usize) -> bool {
        self.buffer.len() >= batch_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn make_raw_log(msg: &str) -> RawLog {
        RawLog::new(Bytes::copy_from_slice(msg.as_bytes()), "test")
    }

    #[test]
    fn push_and_drain() {
        let mut buf = LogBuffer::new(100, DropPolicy::Oldest);
        buf.push(make_raw_log("log1"));
        buf.push(make_raw_log("log2"));
        buf.push(make_raw_log("log3"));
        assert_eq!(buf.len(), 3);

        let batch = buf.drain_batch(2);
        assert_eq!(batch.len(), 2);
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn drain_all() {
        let mut buf = LogBuffer::new(100, DropPolicy::Oldest);
        for i in 0..5 {
            buf.push(make_raw_log(&format!("log{i}")));
        }
        let all = buf.drain_all();
        assert_eq!(all.len(), 5);
        assert!(buf.is_empty());
    }

    #[test]
    fn oldest_drop_policy() {
        let mut buf = LogBuffer::new(3, DropPolicy::Oldest);
        buf.push(make_raw_log("log1"));
        buf.push(make_raw_log("log2"));
        buf.push(make_raw_log("log3"));
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.dropped_count(), 0);

        // 4번째 추가 시 가장 오래된 것이 드롭됨
        let dropped = buf.push(make_raw_log("log4"));
        assert!(dropped);
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.dropped_count(), 1);
    }

    #[test]
    fn newest_drop_policy() {
        let mut buf = LogBuffer::new(2, DropPolicy::Newest);
        buf.push(make_raw_log("log1"));
        buf.push(make_raw_log("log2"));

        // 3번째는 거부됨
        let dropped = buf.push(make_raw_log("log3"));
        assert!(dropped);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.dropped_count(), 1);
    }

    #[test]
    fn utilization_calculation() {
        let mut buf = LogBuffer::new(100, DropPolicy::Oldest);
        assert_eq!(buf.utilization(), 0.0);

        for i in 0..50 {
            buf.push(make_raw_log(&format!("log{i}")));
        }
        let util = buf.utilization();
        assert!(util > 0.49 && util < 0.51);
    }

    #[test]
    fn should_flush() {
        let mut buf = LogBuffer::new(100, DropPolicy::Oldest);
        assert!(!buf.should_flush(10));

        for i in 0..10 {
            buf.push(make_raw_log(&format!("log{i}")));
        }
        assert!(buf.should_flush(10));
        assert!(!buf.should_flush(11));
    }

    #[test]
    fn total_received_tracks_all() {
        let mut buf = LogBuffer::new(2, DropPolicy::Oldest);
        buf.push(make_raw_log("1"));
        buf.push(make_raw_log("2"));
        buf.push(make_raw_log("3")); // drops 1

        assert_eq!(buf.total_received(), 3);
        assert_eq!(buf.dropped_count(), 1);
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn drain_batch_larger_than_buffer() {
        let mut buf = LogBuffer::new(100, DropPolicy::Oldest);
        buf.push(make_raw_log("log1"));
        buf.push(make_raw_log("log2"));

        let batch = buf.drain_batch(100);
        assert_eq!(batch.len(), 2); // returns what's available
        assert!(buf.is_empty());
    }
}
