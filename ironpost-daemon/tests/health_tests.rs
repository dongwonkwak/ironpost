//! Health aggregation tests.
//!
//! Tests the health status aggregation logic and module health reporting.

use ironpost_core::pipeline::HealthStatus;
use ironpost_daemon::health::{ModuleHealth, aggregate_status};

#[test]
fn test_aggregate_status_all_healthy() {
    // Given: All modules are healthy
    let modules = vec![
        ModuleHealth {
            name: "ebpf-engine".to_string(),
            enabled: true,
            status: HealthStatus::Healthy,
        },
        ModuleHealth {
            name: "log-pipeline".to_string(),
            enabled: true,
            status: HealthStatus::Healthy,
        },
        ModuleHealth {
            name: "container-guard".to_string(),
            enabled: true,
            status: HealthStatus::Healthy,
        },
    ];

    // When: Aggregating status
    let status = aggregate_status(&modules);

    // Then: Overall status should be Healthy
    assert!(
        status.is_healthy(),
        "all healthy modules should result in healthy status"
    );
}

#[test]
fn test_aggregate_status_one_degraded() {
    // Given: One module is degraded
    let modules = vec![
        ModuleHealth {
            name: "ebpf-engine".to_string(),
            enabled: true,
            status: HealthStatus::Healthy,
        },
        ModuleHealth {
            name: "log-pipeline".to_string(),
            enabled: true,
            status: HealthStatus::Degraded("high buffer usage".to_string()),
        },
        ModuleHealth {
            name: "container-guard".to_string(),
            enabled: true,
            status: HealthStatus::Healthy,
        },
    ];

    // When: Aggregating status
    let status = aggregate_status(&modules);

    // Then: Overall status should be Degraded with reason
    assert!(
        matches!(status, HealthStatus::Degraded(_)),
        "one degraded module should result in degraded status"
    );
    if let HealthStatus::Degraded(reason) = &status {
        assert!(
            reason.contains("log-pipeline"),
            "degraded reason should mention the module name"
        );
        assert!(
            reason.contains("high buffer usage"),
            "degraded reason should include the original reason"
        );
    } else {
        panic!("expected Degraded status, got: {:?}", status);
    }
}

#[test]
fn test_aggregate_status_one_unhealthy() {
    // Given: One module is unhealthy
    let modules = vec![
        ModuleHealth {
            name: "ebpf-engine".to_string(),
            enabled: true,
            status: HealthStatus::Healthy,
        },
        ModuleHealth {
            name: "log-pipeline".to_string(),
            enabled: true,
            status: HealthStatus::Unhealthy("crash detected".to_string()),
        },
        ModuleHealth {
            name: "container-guard".to_string(),
            enabled: true,
            status: HealthStatus::Healthy,
        },
    ];

    // When: Aggregating status
    let status = aggregate_status(&modules);

    // Then: Overall status should be Unhealthy
    assert!(
        status.is_unhealthy(),
        "one unhealthy module should result in unhealthy status"
    );
    if let HealthStatus::Unhealthy(reason) = &status {
        assert!(
            reason.contains("log-pipeline"),
            "unhealthy reason should mention the module name"
        );
        assert!(
            reason.contains("crash detected"),
            "unhealthy reason should include the original reason"
        );
    } else {
        panic!("expected Unhealthy status, got: {:?}", status);
    }
}

#[test]
fn test_aggregate_status_unhealthy_takes_precedence_over_degraded() {
    // Given: One unhealthy and one degraded module
    let modules = vec![
        ModuleHealth {
            name: "ebpf-engine".to_string(),
            enabled: true,
            status: HealthStatus::Degraded("slow performance".to_string()),
        },
        ModuleHealth {
            name: "log-pipeline".to_string(),
            enabled: true,
            status: HealthStatus::Unhealthy("parser failed".to_string()),
        },
    ];

    // When: Aggregating status
    let status = aggregate_status(&modules);

    // Then: Overall status should be Unhealthy (worst status wins)
    assert!(
        status.is_unhealthy(),
        "unhealthy should take precedence over degraded"
    );
}

#[test]
fn test_aggregate_status_multiple_unhealthy_modules() {
    // Given: Multiple unhealthy modules
    let modules = vec![
        ModuleHealth {
            name: "ebpf-engine".to_string(),
            enabled: true,
            status: HealthStatus::Unhealthy("XDP detach failed".to_string()),
        },
        ModuleHealth {
            name: "log-pipeline".to_string(),
            enabled: true,
            status: HealthStatus::Unhealthy("buffer overflow".to_string()),
        },
    ];

    // When: Aggregating status
    let status = aggregate_status(&modules);

    // Then: Overall status should include all unhealthy reasons
    assert!(status.is_unhealthy(), "multiple unhealthy modules should result in unhealthy status");
    if let HealthStatus::Unhealthy(reason) = &status {
        assert!(
            reason.contains("ebpf-engine"),
            "should mention first unhealthy module"
        );
        assert!(
            reason.contains("log-pipeline"),
            "should mention second unhealthy module"
        );
        assert!(
            reason.contains("XDP detach failed"),
            "should include first reason"
        );
        assert!(
            reason.contains("buffer overflow"),
            "should include second reason"
        );
    } else {
        panic!("expected Unhealthy status, got: {:?}", status);
    }
}

#[test]
fn test_aggregate_status_disabled_modules_ignored() {
    // Given: Mix of enabled and disabled modules, with disabled unhealthy
    let modules = vec![
        ModuleHealth {
            name: "ebpf-engine".to_string(),
            enabled: false,
            status: HealthStatus::Unhealthy("should be ignored".to_string()),
        },
        ModuleHealth {
            name: "log-pipeline".to_string(),
            enabled: true,
            status: HealthStatus::Healthy,
        },
    ];

    // When: Aggregating status
    let status = aggregate_status(&modules);

    // Then: Disabled modules should be ignored
    assert!(
        status.is_healthy(),
        "disabled modules should not affect health status"
    );
}

#[test]
fn test_aggregate_status_empty_modules() {
    // Given: No modules
    let modules = vec![];

    // When: Aggregating status
    let status = aggregate_status(&modules);

    // Then: Should be healthy (no failures)
    assert!(
        status.is_healthy(),
        "empty module list should be considered healthy"
    );
}

#[test]
fn test_aggregate_status_all_disabled() {
    // Given: All modules disabled
    let modules = vec![
        ModuleHealth {
            name: "ebpf-engine".to_string(),
            enabled: false,
            status: HealthStatus::Healthy,
        },
        ModuleHealth {
            name: "log-pipeline".to_string(),
            enabled: false,
            status: HealthStatus::Healthy,
        },
    ];

    // When: Aggregating status
    let status = aggregate_status(&modules);

    // Then: Should be healthy (no enabled modules to fail)
    assert!(
        status.is_healthy(),
        "all disabled modules should result in healthy status"
    );
}

#[test]
fn test_aggregate_status_combines_multiple_degraded_reasons() {
    // Given: Multiple degraded modules
    let modules = vec![
        ModuleHealth {
            name: "ebpf-engine".to_string(),
            enabled: true,
            status: HealthStatus::Degraded("packet loss detected".to_string()),
        },
        ModuleHealth {
            name: "log-pipeline".to_string(),
            enabled: true,
            status: HealthStatus::Degraded("slow parser".to_string()),
        },
    ];

    // When: Aggregating status
    let status = aggregate_status(&modules);

    // Then: Should combine all degraded reasons
    assert!(
        matches!(status, HealthStatus::Degraded(_)),
        "multiple degraded modules should result in degraded status"
    );
    if let HealthStatus::Degraded(reason) = &status {
        assert!(
            reason.contains("ebpf-engine"),
            "should mention first degraded module"
        );
        assert!(
            reason.contains("log-pipeline"),
            "should mention second degraded module"
        );
        assert!(
            reason.contains("packet loss"),
            "should include first reason"
        );
        assert!(
            reason.contains("slow parser"),
            "should include second reason"
        );
    } else {
        panic!("expected Degraded status, got: {:?}", status);
    }
}

#[test]
fn test_aggregate_status_long_module_names() {
    // Given: Modules with very long names
    let long_name = "a".repeat(200);
    let modules = vec![ModuleHealth {
        name: long_name.clone(),
        enabled: true,
        status: HealthStatus::Unhealthy("error".to_string()),
    }];

    // When: Aggregating status
    let status = aggregate_status(&modules);

    // Then: Should handle long names without panic
    assert!(status.is_unhealthy(), "should handle long module names");
    if let HealthStatus::Unhealthy(reason) = &status {
        assert!(
            reason.contains(&long_name),
            "should include the long module name"
        );
    }
}

#[test]
fn test_aggregate_status_special_characters_in_reason() {
    // Given: Module with special characters in reason
    let modules = vec![ModuleHealth {
        name: "test-module".to_string(),
        enabled: true,
        status: HealthStatus::Degraded("error: failed; retry=3".to_string()),
    }];

    // When: Aggregating status
    let status = aggregate_status(&modules);

    // Then: Should preserve special characters
    assert!(
        matches!(status, HealthStatus::Degraded(_)),
        "should handle special characters"
    );
    if let HealthStatus::Degraded(reason) = &status {
        assert!(
            reason.contains("error: failed; retry=3"),
            "should preserve special characters in reason"
        );
    }
}

#[test]
fn test_aggregate_status_unicode_in_module_name() {
    // Given: Module with unicode characters
    let modules = vec![ModuleHealth {
        name: "로그-파이프라인".to_string(),
        enabled: true,
        status: HealthStatus::Healthy,
    }];

    // When: Aggregating status
    let status = aggregate_status(&modules);

    // Then: Should handle unicode without panic
    assert!(status.is_healthy(), "should handle unicode in module names");
}
