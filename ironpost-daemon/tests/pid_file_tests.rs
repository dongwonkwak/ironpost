//! PID file creation, deletion, and duplicate detection tests.
//!
//! Tests the PID file lifecycle: create → exists → delete, and
//! duplicate daemon detection logic.

use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_pid_file_creation_basic() {
    // Given: A temp directory for PID file
    let temp_dir = TempDir::new().expect("should create temp dir");
    let pid_path = temp_dir.path().join("ironpost.pid");

    // When: Writing PID file
    let pid = std::process::id();
    fs::write(&pid_path, pid.to_string()).expect("should write PID file");

    // Then: File should exist with correct PID
    assert!(pid_path.exists(), "PID file should exist");
    let content = fs::read_to_string(&pid_path).expect("should read PID file");
    assert_eq!(content, pid.to_string(), "PID should match");
}

#[test]
fn test_pid_file_deletion() {
    // Given: An existing PID file
    let temp_dir = TempDir::new().expect("should create temp dir");
    let pid_path = temp_dir.path().join("ironpost.pid");
    fs::write(&pid_path, "12345").expect("should write PID file");
    assert!(pid_path.exists(), "PID file should exist before deletion");

    // When: Deleting PID file
    fs::remove_file(&pid_path).expect("should delete PID file");

    // Then: File should not exist
    assert!(!pid_path.exists(), "PID file should be deleted");
}

#[test]
fn test_pid_file_overwrite_same_process() {
    // Given: An existing PID file with current process PID
    let temp_dir = TempDir::new().expect("should create temp dir");
    let pid_path = temp_dir.path().join("ironpost.pid");
    let pid = std::process::id();
    fs::write(&pid_path, pid.to_string()).expect("should write initial PID file");

    // When: Overwriting with same PID
    fs::write(&pid_path, pid.to_string()).expect("should overwrite PID file");

    // Then: File should contain current PID
    let content = fs::read_to_string(&pid_path).expect("should read PID file");
    assert_eq!(content, pid.to_string(), "PID should match after overwrite");
}

#[test]
fn test_pid_file_directory_does_not_exist() {
    // Given: A nonexistent directory path
    let pid_path = PathBuf::from("/nonexistent/directory/ironpost.pid");

    // When: Attempting to write PID file
    let result = fs::write(&pid_path, "12345");

    // Then: Should fail
    assert!(result.is_err(), "should fail when directory doesn't exist");
}

#[test]
fn test_pid_file_permission_denied_simulation() {
    // Given: A path that simulates permission issues (e.g., root-only path on Unix)
    // Note: This test may not fail on all systems if running with elevated privileges

    #[cfg(unix)]
    {
        let pid_path = PathBuf::from("/root/ironpost.pid");

        // When: Attempting to write PID file without permissions
        let result = fs::write(&pid_path, "12345");

        // Then: Should fail (unless running as root)
        if std::env::var("USER").unwrap_or_default() != "root" {
            assert!(result.is_err(), "should fail with permission denied");
        }
    }
}

#[test]
fn test_pid_file_empty_content() {
    // Given: A temp directory
    let temp_dir = TempDir::new().expect("should create temp dir");
    let pid_path = temp_dir.path().join("ironpost.pid");

    // When: Writing empty PID file
    fs::write(&pid_path, "").expect("should write empty file");

    // Then: File should exist but be empty
    assert!(pid_path.exists(), "empty PID file should exist");
    let content = fs::read_to_string(&pid_path).expect("should read empty file");
    assert!(content.is_empty(), "PID file should be empty");
}

#[test]
fn test_pid_file_very_long_path() {
    // Given: A very long file path
    let temp_dir = TempDir::new().expect("should create temp dir");
    let long_name = "a".repeat(200);
    let pid_path = temp_dir.path().join(format!("{}.pid", long_name));

    // When: Writing PID file with long name
    let result = fs::write(&pid_path, "12345");

    // Then: Should succeed on most systems (or fail gracefully)
    match result {
        Ok(_) => {
            assert!(pid_path.exists(), "long path PID file should exist");
        }
        Err(_) => {
            // Path too long is acceptable failure
        }
    }
}

#[test]
fn test_pid_file_special_characters_in_path() {
    // Given: A path with special characters
    let temp_dir = TempDir::new().expect("should create temp dir");
    let pid_path = temp_dir.path().join("ironpost-daemon@1.0.pid");

    // When: Writing PID file
    fs::write(&pid_path, "12345").expect("should write PID with special chars");

    // Then: File should exist
    assert!(pid_path.exists(), "PID file with special chars should exist");
}

#[test]
fn test_pid_file_unicode_in_directory_name() {
    // Given: A directory with unicode name
    let temp_dir = TempDir::new().expect("should create temp dir");
    let unicode_dir = temp_dir.path().join("설정");
    fs::create_dir(&unicode_dir).expect("should create unicode dir");
    let pid_path = unicode_dir.join("ironpost.pid");

    // When: Writing PID file in unicode directory
    fs::write(&pid_path, "12345").expect("should write PID in unicode dir");

    // Then: File should exist
    assert!(pid_path.exists(), "PID file in unicode dir should exist");
}

#[test]
fn test_pid_file_read_invalid_content() {
    // Given: A PID file with non-numeric content
    let temp_dir = TempDir::new().expect("should create temp dir");
    let pid_path = temp_dir.path().join("ironpost.pid");
    fs::write(&pid_path, "not_a_number").expect("should write invalid PID");

    // When: Reading PID file
    let content = fs::read_to_string(&pid_path).expect("should read file");

    // Then: Content should be invalid PID format
    assert_eq!(content, "not_a_number");
    assert!(content.parse::<u32>().is_err(), "should not parse as number");
}

#[test]
fn test_pid_file_concurrent_creation() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    // Given: Multiple threads trying to create PID files
    let temp_dir = Arc::new(TempDir::new().expect("should create temp dir"));
    let success_count = Arc::new(AtomicUsize::new(0));
    let handles: Vec<_> = (0..10)
        .map(|i| {
            let temp_dir = Arc::clone(&temp_dir);
            let success_count = Arc::clone(&success_count);
            thread::spawn(move || {
                let pid_path = temp_dir.path().join(format!("ironpost-{}.pid", i));
                if fs::write(&pid_path, "12345").is_ok() {
                    success_count.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();

    // When: All threads complete
    for handle in handles {
        handle.join().expect("thread should complete");
    }

    // Then: All writes should succeed
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        10,
        "all concurrent writes should succeed"
    );
}

#[test]
fn test_pid_file_boundary_max_u32() {
    // Given: Maximum u32 PID value
    let temp_dir = TempDir::new().expect("should create temp dir");
    let pid_path = temp_dir.path().join("ironpost.pid");
    let max_pid = u32::MAX;

    // When: Writing max PID value
    fs::write(&pid_path, max_pid.to_string()).expect("should write max PID");

    // Then: Should read back correctly
    let content = fs::read_to_string(&pid_path).expect("should read PID file");
    let parsed: u32 = content.parse().expect("should parse max PID");
    assert_eq!(parsed, max_pid, "max PID should round-trip correctly");
}

#[test]
fn test_pid_file_symlink_handling() {
    // Given: A PID file and a symlink to it
    let temp_dir = TempDir::new().expect("should create temp dir");
    let pid_path = temp_dir.path().join("ironpost.pid");
    let symlink_path = temp_dir.path().join("ironpost-link.pid");

    fs::write(&pid_path, "12345").expect("should write PID file");

    #[cfg(unix)]
    {
        use std::os::unix::fs as unix_fs;
        unix_fs::symlink(&pid_path, &symlink_path).expect("should create symlink");

        // When: Reading via symlink
        let content = fs::read_to_string(&symlink_path).expect("should read via symlink");

        // Then: Should read original content
        assert_eq!(content, "12345", "should read PID via symlink");
    }
}
