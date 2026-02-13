//! 플러그인 시스템 — 모듈 등록, 생명주기 관리, 동적 확장
//!
//! [`Plugin`] trait은 [`Pipeline`](crate::pipeline::Pipeline)의 상위 추상화로,
//! 모듈 메타데이터와 초기화 단계를 추가합니다.
//!
//! [`PluginRegistry`]는 플러그인의 등록, 해제, 생명주기 관리를 담당합니다.
//!
//! # 생명주기
//! ```text
//! Created → init() → Initialized → start() → Running → stop() → Stopped
//! ```

use std::fmt;
use std::future::Future;

use serde::{Deserialize, Serialize};

use crate::error::{IronpostError, PluginError};
use crate::pipeline::{BoxFuture, HealthStatus};

// ─── PluginType ──────────────────────────────────────────────────────

/// 플러그인 유형
///
/// 기본 제공 모듈 유형과 사용자 정의 유형을 구분합니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginType {
    /// 네트워크 탐지 (eBPF 등)
    Detector,
    /// 로그 수집/분석 파이프라인
    LogPipeline,
    /// SBOM/취약점 스캐너
    Scanner,
    /// 컨테이너 격리/정책 집행
    Enforcer,
    /// 사용자 정의 플러그인
    Custom(String),
}

impl fmt::Display for PluginType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Detector => write!(f, "detector"),
            Self::LogPipeline => write!(f, "log-pipeline"),
            Self::Scanner => write!(f, "scanner"),
            Self::Enforcer => write!(f, "enforcer"),
            Self::Custom(name) => write!(f, "custom:{name}"),
        }
    }
}

// ─── PluginInfo ──────────────────────────────────────────────────────

/// 플러그인 메타데이터
///
/// 플러그인 등록 시 고유 이름, 버전, 설명, 유형 정보를 제공합니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    /// 플러그인 고유 이름 (예: `"ebpf-engine"`)
    pub name: String,
    /// 플러그인 버전 (semver, 예: `"0.1.0"`)
    pub version: String,
    /// 플러그인 설명
    pub description: String,
    /// 플러그인 유형
    pub plugin_type: PluginType,
}

// ─── PluginState ─────────────────────────────────────────────────────

/// 플러그인 생명주기 상태
///
/// 상태 전환:
/// - `Created` → `init()` → `Initialized`
/// - `Initialized` → `start()` → `Running`
/// - `Running` → `stop()` → `Stopped`
/// - 에러 발생 시 → `Failed`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginState {
    /// 생성됨 (init 전)
    Created,
    /// 초기화 완료 (start 가능)
    Initialized,
    /// 실행 중
    Running,
    /// 정지됨
    Stopped,
    /// 오류 상태
    Failed,
}

impl fmt::Display for PluginState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Initialized => write!(f, "initialized"),
            Self::Running => write!(f, "running"),
            Self::Stopped => write!(f, "stopped"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

// ─── Plugin Trait ────────────────────────────────────────────────────

/// 모든 모듈이 구현하는 플러그인 trait
///
/// [`Pipeline`](crate::pipeline::Pipeline)의 상위 추상화로,
/// 메타데이터 조회와 초기화 단계를 추가합니다.
///
/// # 생명주기
/// ```text
/// Created → init() → Initialized → start() → Running → stop() → Stopped
/// ```
///
/// # 구현 예시
/// ```ignore
/// struct MyPlugin {
///     info: PluginInfo,
///     state: PluginState,
/// }
///
/// impl Plugin for MyPlugin {
///     fn info(&self) -> &PluginInfo { &self.info }
///     fn state(&self) -> PluginState { self.state }
///
///     async fn init(&mut self) -> Result<(), IronpostError> {
///         self.state = PluginState::Initialized;
///         Ok(())
///     }
///     async fn start(&mut self) -> Result<(), IronpostError> {
///         self.state = PluginState::Running;
///         Ok(())
///     }
///     async fn stop(&mut self) -> Result<(), IronpostError> {
///         self.state = PluginState::Stopped;
///         Ok(())
///     }
///     async fn health_check(&self) -> HealthStatus {
///         HealthStatus::Healthy
///     }
/// }
/// ```
pub trait Plugin: Send + Sync {
    /// 플러그인 메타데이터를 반환합니다.
    fn info(&self) -> &PluginInfo;

    /// 현재 플러그인 상태를 반환합니다.
    fn state(&self) -> PluginState;

    /// 플러그인을 초기화합니다.
    ///
    /// 리소스 할당, 설정 검증 등을 수행합니다.
    /// `Created` 상태에서만 호출 가능합니다.
    fn init(&mut self) -> impl Future<Output = Result<(), IronpostError>> + Send;

    /// 플러그인을 시작합니다.
    ///
    /// `Initialized` 또는 `Stopped` 상태에서만 호출 가능합니다.
    fn start(&mut self) -> impl Future<Output = Result<(), IronpostError>> + Send;

    /// 플러그인을 정지합니다.
    ///
    /// `Running` 상태에서만 호출 가능합니다.
    /// Graceful shutdown을 수행합니다.
    fn stop(&mut self) -> impl Future<Output = Result<(), IronpostError>> + Send;

    /// 플러그인의 건강 상태를 확인합니다.
    fn health_check(&self) -> impl Future<Output = HealthStatus> + Send;
}

// ─── DynPlugin Trait ─────────────────────────────────────────────────

/// dyn-compatible 플러그인 trait
///
/// `Plugin` trait은 RPITIT를 사용하므로 `dyn Plugin`이 불가합니다.
/// `DynPlugin`은 `BoxFuture`를 반환하여 `Vec<Box<dyn DynPlugin>>`으로
/// 플러그인을 동적 관리할 수 있게 합니다.
pub trait DynPlugin: Send + Sync {
    /// 플러그인 메타데이터를 반환합니다.
    fn info(&self) -> &PluginInfo;

    /// 현재 플러그인 상태를 반환합니다.
    fn state(&self) -> PluginState;

    /// 플러그인을 초기화합니다.
    fn init(&mut self) -> BoxFuture<'_, Result<(), IronpostError>>;

    /// 플러그인을 시작합니다.
    fn start(&mut self) -> BoxFuture<'_, Result<(), IronpostError>>;

    /// 플러그인을 정지합니다.
    fn stop(&mut self) -> BoxFuture<'_, Result<(), IronpostError>>;

    /// 플러그인의 건강 상태를 확인합니다.
    fn health_check(&self) -> BoxFuture<'_, HealthStatus>;
}

/// Plugin을 구현한 타입은 자동으로 DynPlugin도 구현됩니다.
impl<T: Plugin> DynPlugin for T {
    fn info(&self) -> &PluginInfo {
        Plugin::info(self)
    }

    fn state(&self) -> PluginState {
        Plugin::state(self)
    }

    fn init(&mut self) -> BoxFuture<'_, Result<(), IronpostError>> {
        Box::pin(Plugin::init(self))
    }

    fn start(&mut self) -> BoxFuture<'_, Result<(), IronpostError>> {
        Box::pin(Plugin::start(self))
    }

    fn stop(&mut self) -> BoxFuture<'_, Result<(), IronpostError>> {
        Box::pin(Plugin::stop(self))
    }

    fn health_check(&self) -> BoxFuture<'_, HealthStatus> {
        Box::pin(Plugin::health_check(self))
    }
}

// ─── PluginRegistry ──────────────────────────────────────────────────

/// 플러그인 레지스트리
///
/// 플러그인의 등록, 해제, 생명주기 관리를 담당합니다.
/// 등록 순서가 보존되며, 생산자를 먼저 등록하고 소비자를 나중에 등록합니다.
///
/// # 사용 예시
/// ```ignore
/// let mut registry = PluginRegistry::new();
/// registry.register(Box::new(ebpf_plugin))?;
/// registry.register(Box::new(log_plugin))?;
///
/// registry.init_all().await?;
/// registry.start_all().await?;
///
/// // ... 실행 중 ...
///
/// registry.stop_all().await?;
/// ```
pub struct PluginRegistry {
    plugins: Vec<Box<dyn DynPlugin>>,
}

impl PluginRegistry {
    /// 빈 레지스트리를 생성합니다.
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// 플러그인을 등록합니다.
    ///
    /// 동일한 이름의 플러그인이 이미 등록되어 있으면 에러를 반환합니다.
    /// 등록 순서가 보존되며, 생산자를 먼저 등록해야 합니다.
    pub fn register(&mut self, plugin: Box<dyn DynPlugin>) -> Result<(), IronpostError> {
        let name = plugin.info().name.clone();
        if self.plugins.iter().any(|p| p.info().name == name) {
            return Err(PluginError::AlreadyRegistered { name }.into());
        }
        self.plugins.push(plugin);
        Ok(())
    }

    /// 플러그인을 해제합니다.
    ///
    /// 존재하지 않는 플러그인이면 에러를 반환합니다.
    /// 해제된 플러그인의 소유권을 반환합니다.
    pub fn unregister(&mut self, name: &str) -> Result<Box<dyn DynPlugin>, IronpostError> {
        let pos = self.plugins.iter().position(|p| p.info().name == name);
        match pos {
            Some(idx) => Ok(self.plugins.remove(idx)),
            None => Err(PluginError::NotFound {
                name: name.to_owned(),
            }
            .into()),
        }
    }

    /// 이름으로 플러그인을 조회합니다.
    pub fn get(&self, name: &str) -> Option<&dyn DynPlugin> {
        self.plugins
            .iter()
            .find(|p| p.info().name == name)
            .map(|p| p.as_ref())
    }

    /// 이름으로 플러그인을 가변 조회합니다.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut dyn DynPlugin> {
        for plugin in &mut self.plugins {
            if plugin.info().name == name {
                return Some(&mut **plugin);
            }
        }
        None
    }

    /// 모든 플러그인을 등록 순서대로 초기화합니다.
    ///
    /// 첫 번째 실패 시 즉시 반환합니다 (fail-fast).
    pub async fn init_all(&mut self) -> Result<(), IronpostError> {
        for plugin in &mut self.plugins {
            plugin.init().await?;
        }
        Ok(())
    }

    /// 모든 플러그인을 등록 순서대로 시작합니다.
    ///
    /// 첫 번째 실패 시 즉시 반환합니다 (fail-fast).
    /// 이미 시작된 플러그인은 롤백하지 않으므로, 호출자가 `stop_all`을 호출해야 합니다.
    pub async fn start_all(&mut self) -> Result<(), IronpostError> {
        for plugin in &mut self.plugins {
            plugin.start().await?;
        }
        Ok(())
    }

    /// 모든 플러그인을 등록 순서대로 정지합니다.
    ///
    /// 생산자가 먼저 정지하여 소비자가 잔여 이벤트를 드레인할 수 있습니다.
    /// 개별 플러그인 정지 실패 시에도 나머지 플러그인의 정지를 계속합니다.
    /// 모든 에러를 수집하여 반환합니다.
    pub async fn stop_all(&mut self) -> Result<(), IronpostError> {
        let mut errors = Vec::new();
        for plugin in &mut self.plugins {
            if let Err(e) = plugin.stop().await {
                errors.push(format!("{}: {}", plugin.info().name, e));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(PluginError::StopFailed(errors.join("; ")).into())
        }
    }

    /// 등록된 플러그인 수를 반환합니다.
    pub fn count(&self) -> usize {
        self.plugins.len()
    }

    /// 등록된 모든 플러그인의 정보를 반환합니다.
    pub fn list(&self) -> Vec<&PluginInfo> {
        self.plugins.iter().map(|p| p.info()).collect()
    }

    /// 모든 플러그인의 건강 상태를 조회합니다.
    pub async fn health_check_all(&self) -> Vec<(String, PluginState, HealthStatus)> {
        let mut statuses = Vec::new();
        for plugin in &self.plugins {
            let name = plugin.info().name.clone();
            let state = plugin.state();
            let health = plugin.health_check().await;
            statuses.push((name, state, health));
        }
        statuses
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PipelineError;

    /// 테스트용 Mock 플러그인
    struct MockPlugin {
        info: PluginInfo,
        state: PluginState,
        fail_on_init: bool,
        fail_on_start: bool,
        fail_on_stop: bool,
    }

    impl MockPlugin {
        fn new(name: &str, plugin_type: PluginType) -> Self {
            Self {
                info: PluginInfo {
                    name: name.to_owned(),
                    version: "0.1.0".to_owned(),
                    description: format!("Mock plugin: {name}"),
                    plugin_type,
                },
                state: PluginState::Created,
                fail_on_init: false,
                fail_on_start: false,
                fail_on_stop: false,
            }
        }

        fn failing_init(mut self) -> Self {
            self.fail_on_init = true;
            self
        }

        fn failing_start(mut self) -> Self {
            self.fail_on_start = true;
            self
        }

        fn failing_stop(mut self) -> Self {
            self.fail_on_stop = true;
            self
        }
    }

    impl Plugin for MockPlugin {
        fn info(&self) -> &PluginInfo {
            &self.info
        }

        fn state(&self) -> PluginState {
            self.state
        }

        async fn init(&mut self) -> Result<(), IronpostError> {
            if self.fail_on_init {
                self.state = PluginState::Failed;
                return Err(PipelineError::InitFailed("mock init failure".to_owned()).into());
            }
            self.state = PluginState::Initialized;
            Ok(())
        }

        async fn start(&mut self) -> Result<(), IronpostError> {
            if self.fail_on_start {
                self.state = PluginState::Failed;
                return Err(PipelineError::InitFailed("mock start failure".to_owned()).into());
            }
            self.state = PluginState::Running;
            Ok(())
        }

        async fn stop(&mut self) -> Result<(), IronpostError> {
            if self.fail_on_stop {
                self.state = PluginState::Failed;
                return Err(PipelineError::InitFailed("mock stop failure".to_owned()).into());
            }
            self.state = PluginState::Stopped;
            Ok(())
        }

        async fn health_check(&self) -> HealthStatus {
            match self.state {
                PluginState::Running => HealthStatus::Healthy,
                PluginState::Failed => HealthStatus::Unhealthy("failed".to_owned()),
                _ => HealthStatus::Degraded("not running".to_owned()),
            }
        }
    }

    // ── PluginType tests ──

    #[test]
    fn plugin_type_display() {
        assert_eq!(PluginType::Detector.to_string(), "detector");
        assert_eq!(PluginType::LogPipeline.to_string(), "log-pipeline");
        assert_eq!(PluginType::Scanner.to_string(), "scanner");
        assert_eq!(PluginType::Enforcer.to_string(), "enforcer");
        assert_eq!(
            PluginType::Custom("my-plugin".to_owned()).to_string(),
            "custom:my-plugin"
        );
    }

    #[test]
    fn plugin_type_equality() {
        assert_eq!(PluginType::Detector, PluginType::Detector);
        assert_ne!(PluginType::Detector, PluginType::Scanner);
        assert_eq!(
            PluginType::Custom("a".to_owned()),
            PluginType::Custom("a".to_owned())
        );
        assert_ne!(
            PluginType::Custom("a".to_owned()),
            PluginType::Custom("b".to_owned())
        );
    }

    #[test]
    fn plugin_type_serialize_deserialize() {
        let pt = PluginType::Scanner;
        let json = serde_json::to_string(&pt).unwrap();
        let deserialized: PluginType = serde_json::from_str(&json).unwrap();
        assert_eq!(pt, deserialized);

        let custom = PluginType::Custom("ext".to_owned());
        let json = serde_json::to_string(&custom).unwrap();
        let deserialized: PluginType = serde_json::from_str(&json).unwrap();
        assert_eq!(custom, deserialized);
    }

    // ── PluginState tests ──

    #[test]
    fn plugin_state_display() {
        assert_eq!(PluginState::Created.to_string(), "created");
        assert_eq!(PluginState::Initialized.to_string(), "initialized");
        assert_eq!(PluginState::Running.to_string(), "running");
        assert_eq!(PluginState::Stopped.to_string(), "stopped");
        assert_eq!(PluginState::Failed.to_string(), "failed");
    }

    #[test]
    fn plugin_state_equality() {
        assert_eq!(PluginState::Created, PluginState::Created);
        assert_ne!(PluginState::Created, PluginState::Running);
    }

    #[test]
    fn plugin_state_serialize_deserialize() {
        let state = PluginState::Running;
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: PluginState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);
    }

    // ── PluginInfo tests ──

    #[test]
    fn plugin_info_clone() {
        let info = PluginInfo {
            name: "test".to_owned(),
            version: "1.0.0".to_owned(),
            description: "Test plugin".to_owned(),
            plugin_type: PluginType::Detector,
        };
        let cloned = info.clone();
        assert_eq!(info.name, cloned.name);
        assert_eq!(info.version, cloned.version);
    }

    #[test]
    fn plugin_info_serialize_deserialize() {
        let info = PluginInfo {
            name: "ebpf-engine".to_owned(),
            version: "0.1.0".to_owned(),
            description: "eBPF network detection".to_owned(),
            plugin_type: PluginType::Detector,
        };
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: PluginInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info.name, deserialized.name);
        assert_eq!(info.version, deserialized.version);
        assert_eq!(info.plugin_type, deserialized.plugin_type);
    }

    // ── Plugin trait lifecycle tests ──

    #[tokio::test]
    async fn plugin_lifecycle_init_start_stop() {
        let mut plugin = MockPlugin::new("test", PluginType::Detector);
        assert_eq!(Plugin::state(&plugin), PluginState::Created);

        Plugin::init(&mut plugin).await.unwrap();
        assert_eq!(Plugin::state(&plugin), PluginState::Initialized);

        Plugin::start(&mut plugin).await.unwrap();
        assert_eq!(Plugin::state(&plugin), PluginState::Running);

        Plugin::stop(&mut plugin).await.unwrap();
        assert_eq!(Plugin::state(&plugin), PluginState::Stopped);
    }

    #[tokio::test]
    async fn plugin_health_check_reflects_state() {
        let mut plugin = MockPlugin::new("test", PluginType::Detector);

        // Created → not running
        let health = Plugin::health_check(&plugin).await;
        assert!(!health.is_healthy());

        Plugin::init(&mut plugin).await.unwrap();
        Plugin::start(&mut plugin).await.unwrap();

        // Running → healthy
        let health = Plugin::health_check(&plugin).await;
        assert!(health.is_healthy());
    }

    #[tokio::test]
    async fn plugin_init_failure_sets_failed_state() {
        let mut plugin = MockPlugin::new("test", PluginType::Detector).failing_init();

        let result = Plugin::init(&mut plugin).await;
        assert!(result.is_err());
        assert_eq!(Plugin::state(&plugin), PluginState::Failed);
    }

    // ── DynPlugin tests ──

    #[tokio::test]
    async fn dyn_plugin_can_be_boxed() {
        let mut plugin: Box<dyn DynPlugin> =
            Box::new(MockPlugin::new("boxed", PluginType::Scanner));

        assert_eq!(plugin.info().name, "boxed");
        assert_eq!(plugin.state(), PluginState::Created);

        plugin.init().await.unwrap();
        assert_eq!(plugin.state(), PluginState::Initialized);

        plugin.start().await.unwrap();
        assert_eq!(plugin.state(), PluginState::Running);

        let health = plugin.health_check().await;
        assert!(health.is_healthy());

        plugin.stop().await.unwrap();
        assert_eq!(plugin.state(), PluginState::Stopped);
    }

    // ── PluginRegistry tests ──

    #[test]
    fn registry_new_is_empty() {
        let registry = PluginRegistry::new();
        assert_eq!(registry.count(), 0);
        assert!(registry.list().is_empty());
    }

    #[test]
    fn registry_default_is_empty() {
        let registry = PluginRegistry::default();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn registry_register_increases_count() {
        let mut registry = PluginRegistry::new();
        let plugin = MockPlugin::new("test", PluginType::Detector);
        registry.register(Box::new(plugin)).unwrap();
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn registry_register_duplicate_name_fails() {
        let mut registry = PluginRegistry::new();
        let plugin1 = MockPlugin::new("dup", PluginType::Detector);
        let plugin2 = MockPlugin::new("dup", PluginType::Scanner);

        registry.register(Box::new(plugin1)).unwrap();
        let err = registry.register(Box::new(plugin2)).unwrap_err();
        assert!(err.to_string().contains("already registered"));
        assert!(err.to_string().contains("dup"));
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn registry_unregister_removes_plugin() {
        let mut registry = PluginRegistry::new();
        let plugin = MockPlugin::new("removable", PluginType::Detector);
        registry.register(Box::new(plugin)).unwrap();
        assert_eq!(registry.count(), 1);

        let removed = registry.unregister("removable").unwrap();
        assert_eq!(removed.info().name, "removable");
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn registry_unregister_not_found_fails() {
        let mut registry = PluginRegistry::new();
        let err = registry
            .unregister("nonexistent")
            .err()
            .expect("should return error");
        assert!(err.to_string().contains("not found"));
        assert!(err.to_string().contains("nonexistent"));
    }

    #[test]
    fn registry_get_returns_plugin() {
        let mut registry = PluginRegistry::new();
        let plugin = MockPlugin::new("lookup", PluginType::Enforcer);
        registry.register(Box::new(plugin)).unwrap();

        let found = registry.get("lookup");
        assert!(found.is_some());
        assert_eq!(found.unwrap().info().name, "lookup");
    }

    #[test]
    fn registry_get_not_found_returns_none() {
        let registry = PluginRegistry::new();
        assert!(registry.get("missing").is_none());
    }

    #[test]
    fn registry_get_mut_returns_mutable_plugin() {
        let mut registry = PluginRegistry::new();
        let plugin = MockPlugin::new("mutable", PluginType::Detector);
        registry.register(Box::new(plugin)).unwrap();

        let found = registry.get_mut("mutable");
        assert!(found.is_some());
        assert_eq!(found.unwrap().info().name, "mutable");
    }

    #[test]
    fn registry_list_returns_all_info() {
        let mut registry = PluginRegistry::new();
        registry
            .register(Box::new(MockPlugin::new("a", PluginType::Detector)))
            .unwrap();
        registry
            .register(Box::new(MockPlugin::new("b", PluginType::Scanner)))
            .unwrap();
        registry
            .register(Box::new(MockPlugin::new("c", PluginType::Enforcer)))
            .unwrap();

        let list = registry.list();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].name, "a");
        assert_eq!(list[1].name, "b");
        assert_eq!(list[2].name, "c");
    }

    #[tokio::test]
    async fn registry_init_all_initializes_plugins() {
        let mut registry = PluginRegistry::new();
        registry
            .register(Box::new(MockPlugin::new("p1", PluginType::Detector)))
            .unwrap();
        registry
            .register(Box::new(MockPlugin::new("p2", PluginType::Scanner)))
            .unwrap();

        registry.init_all().await.unwrap();

        assert_eq!(
            registry.get("p1").unwrap().state(),
            PluginState::Initialized
        );
        assert_eq!(
            registry.get("p2").unwrap().state(),
            PluginState::Initialized
        );
    }

    #[tokio::test]
    async fn registry_init_all_fails_fast() {
        let mut registry = PluginRegistry::new();
        registry
            .register(Box::new(MockPlugin::new("ok", PluginType::Detector)))
            .unwrap();
        registry
            .register(Box::new(
                MockPlugin::new("fail", PluginType::Scanner).failing_init(),
            ))
            .unwrap();
        registry
            .register(Box::new(MockPlugin::new("skipped", PluginType::Enforcer)))
            .unwrap();

        let result = registry.init_all().await;
        assert!(result.is_err());

        // First plugin was initialized, second failed, third was skipped
        assert_eq!(
            registry.get("ok").unwrap().state(),
            PluginState::Initialized
        );
        assert_eq!(registry.get("fail").unwrap().state(), PluginState::Failed);
        assert_eq!(
            registry.get("skipped").unwrap().state(),
            PluginState::Created
        );
    }

    #[tokio::test]
    async fn registry_start_all_starts_plugins() {
        let mut registry = PluginRegistry::new();
        registry
            .register(Box::new(MockPlugin::new("p1", PluginType::Detector)))
            .unwrap();
        registry
            .register(Box::new(MockPlugin::new("p2", PluginType::Scanner)))
            .unwrap();

        registry.init_all().await.unwrap();
        registry.start_all().await.unwrap();

        assert_eq!(registry.get("p1").unwrap().state(), PluginState::Running);
        assert_eq!(registry.get("p2").unwrap().state(), PluginState::Running);
    }

    #[tokio::test]
    async fn registry_start_all_fails_fast() {
        let mut registry = PluginRegistry::new();
        registry
            .register(Box::new(MockPlugin::new("ok", PluginType::Detector)))
            .unwrap();
        registry
            .register(Box::new(
                MockPlugin::new("fail", PluginType::Scanner).failing_start(),
            ))
            .unwrap();

        registry.init_all().await.unwrap();
        let result = registry.start_all().await;
        assert!(result.is_err());

        assert_eq!(registry.get("ok").unwrap().state(), PluginState::Running);
        assert_eq!(registry.get("fail").unwrap().state(), PluginState::Failed);
    }

    #[tokio::test]
    async fn registry_stop_all_stops_plugins() {
        let mut registry = PluginRegistry::new();
        registry
            .register(Box::new(MockPlugin::new("p1", PluginType::Detector)))
            .unwrap();
        registry
            .register(Box::new(MockPlugin::new("p2", PluginType::Scanner)))
            .unwrap();

        registry.init_all().await.unwrap();
        registry.start_all().await.unwrap();
        registry.stop_all().await.unwrap();

        assert_eq!(registry.get("p1").unwrap().state(), PluginState::Stopped);
        assert_eq!(registry.get("p2").unwrap().state(), PluginState::Stopped);
    }

    #[tokio::test]
    async fn registry_stop_all_continues_on_error() {
        let mut registry = PluginRegistry::new();
        registry
            .register(Box::new(
                MockPlugin::new("fail", PluginType::Detector).failing_stop(),
            ))
            .unwrap();
        registry
            .register(Box::new(MockPlugin::new("ok", PluginType::Scanner)))
            .unwrap();

        registry.init_all().await.unwrap();
        registry.start_all().await.unwrap();

        let result = registry.stop_all().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("fail"));

        // Second plugin should still have been stopped
        assert_eq!(registry.get("ok").unwrap().state(), PluginState::Stopped);
    }

    #[tokio::test]
    async fn registry_health_check_all() {
        let mut registry = PluginRegistry::new();
        registry
            .register(Box::new(MockPlugin::new("running", PluginType::Detector)))
            .unwrap();
        registry
            .register(Box::new(MockPlugin::new("created", PluginType::Scanner)))
            .unwrap();

        // Only init+start the first one
        if let Some(p) = registry.get_mut("running") {
            p.init().await.unwrap();
            p.start().await.unwrap();
        }

        let statuses = registry.health_check_all().await;
        assert_eq!(statuses.len(), 2);

        let (name1, state1, health1) = &statuses[0];
        assert_eq!(name1, "running");
        assert_eq!(*state1, PluginState::Running);
        assert!(health1.is_healthy());

        let (name2, state2, _health2) = &statuses[1];
        assert_eq!(name2, "created");
        assert_eq!(*state2, PluginState::Created);
    }

    #[tokio::test]
    async fn registry_full_lifecycle() {
        let mut registry = PluginRegistry::new();
        registry
            .register(Box::new(MockPlugin::new("ebpf", PluginType::Detector)))
            .unwrap();
        registry
            .register(Box::new(MockPlugin::new("log", PluginType::LogPipeline)))
            .unwrap();
        registry
            .register(Box::new(MockPlugin::new("sbom", PluginType::Scanner)))
            .unwrap();
        registry
            .register(Box::new(MockPlugin::new("guard", PluginType::Enforcer)))
            .unwrap();

        assert_eq!(registry.count(), 4);

        // Init all
        registry.init_all().await.unwrap();
        for info in registry.list() {
            assert_eq!(
                registry.get(&info.name).unwrap().state(),
                PluginState::Initialized
            );
        }

        // Start all
        registry.start_all().await.unwrap();
        for info in registry.list() {
            assert_eq!(
                registry.get(&info.name).unwrap().state(),
                PluginState::Running
            );
        }

        // Health check
        let statuses = registry.health_check_all().await;
        assert!(statuses.iter().all(|(_, _, h)| h.is_healthy()));

        // Stop all
        registry.stop_all().await.unwrap();
        for info in registry.list() {
            assert_eq!(
                registry.get(&info.name).unwrap().state(),
                PluginState::Stopped
            );
        }
    }

    #[test]
    fn registry_preserves_registration_order() {
        let mut registry = PluginRegistry::new();
        let names = ["alpha", "beta", "gamma", "delta"];

        for name in &names {
            let plugin = MockPlugin::new(name, PluginType::Detector);
            registry.register(Box::new(plugin)).unwrap();
        }

        let list: Vec<&str> = registry
            .list()
            .iter()
            .map(|info| info.name.as_str())
            .collect();
        assert_eq!(list, names);
    }

    #[test]
    fn registry_unregister_middle_preserves_order() {
        let mut registry = PluginRegistry::new();
        registry
            .register(Box::new(MockPlugin::new("a", PluginType::Detector)))
            .unwrap();
        registry
            .register(Box::new(MockPlugin::new("b", PluginType::Scanner)))
            .unwrap();
        registry
            .register(Box::new(MockPlugin::new("c", PluginType::Enforcer)))
            .unwrap();

        registry.unregister("b").unwrap();

        let list: Vec<&str> = registry
            .list()
            .iter()
            .map(|info| info.name.as_str())
            .collect();
        assert_eq!(list, vec!["a", "c"]);
    }

    // ── PluginError tests ──

    #[test]
    fn plugin_error_already_registered_display() {
        let err = PluginError::AlreadyRegistered {
            name: "test".to_owned(),
        };
        assert_eq!(err.to_string(), "plugin already registered: test");
    }

    #[test]
    fn plugin_error_not_found_display() {
        let err = PluginError::NotFound {
            name: "missing".to_owned(),
        };
        assert_eq!(err.to_string(), "plugin not found: missing");
    }

    #[test]
    fn plugin_error_invalid_state_display() {
        let err = PluginError::InvalidState {
            name: "test".to_owned(),
            current: "created".to_owned(),
            expected: "initialized".to_owned(),
        };
        assert!(err.to_string().contains("test"));
        assert!(err.to_string().contains("created"));
        assert!(err.to_string().contains("initialized"));
    }

    #[test]
    fn plugin_error_stop_failed_display() {
        let err = PluginError::StopFailed("p1: timeout; p2: connection lost".to_owned());
        assert!(err.to_string().contains("p1: timeout"));
        assert!(err.to_string().contains("p2: connection lost"));
    }

    #[test]
    fn plugin_error_converts_to_ironpost_error() {
        let plugin_err = PluginError::NotFound {
            name: "test".to_owned(),
        };
        let err: IronpostError = plugin_err.into();
        assert!(matches!(err, IronpostError::Plugin(_)));
        assert!(err.to_string().contains("test"));
    }
}
