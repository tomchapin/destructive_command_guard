//! Memory leak detection tests for DCG
//!
//! These tests verify that DCG's hot paths don't leak memory
//! when processing many inputs. Critical because DCG runs on
//! every Bash command in Claude Code sessions.
//!
//! MUST run with: cargo test --test memory_tests --release -- --test-threads=1 --nocapture
//!
//! ## Why These Tests Matter
//!
//! DCG is invoked on EVERY command in Claude Code sessions:
//! - 1000+ commands per session is common
//! - Memory leaks compound across invocations
//! - Even 1KB/command = 1MB leaked per session
//!
//! ## Platform Support
//!
//! - Linux: Full support (reads /proc/self/statm)
//! - macOS/Windows: Tests skip gracefully

#![cfg(test)]

use std::hint::black_box;

/// Get current memory usage via /proc/self/statm (Linux)
/// Returns resident set size in bytes
fn get_memory_usage() -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        let statm = fs::read_to_string("/proc/self/statm").ok()?;
        let rss_pages: usize = statm.split_whitespace().nth(1)?.parse().ok()?;
        
        // Use getconf to avoid unsafe libc call
        let page_size = std::process::Command::new("getconf")
            .arg("PAGESIZE")
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(4096);
            
        Some(rss_pages * page_size)
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Memory test helper with detailed logging
///
/// # Arguments
/// * `name` - Test name for logging
/// * `iterations` - Number of times to run the closure
/// * `max_growth_bytes` - Maximum allowed memory growth
/// * `f` - Closure to run repeatedly
///
/// # Behavior
/// 1. Warms up with 10 iterations (triggers lazy initialization)
/// 2. Measures baseline memory
/// 3. Runs iterations with periodic progress logging
/// 4. Asserts final growth is within budget
///
/// # Flakiness Mitigation
/// - Generous budgets (1-2MB) accommodate measurement noise
/// - Warm-up phase triggers lazy_static initialization
/// - Progress logging helps identify gradual leaks vs noise
pub fn assert_no_leak<F>(name: &str, iterations: usize, max_growth_bytes: usize, mut f: F)
where
    F: FnMut(),
{
    println!("memory_{}: warming up (10 iterations)...", name);
    for _ in 0..10 { f(); }
    
    // Force deallocation of any pending drops
    drop(Vec::<u8>::with_capacity(1024 * 1024));
    
    let Some(baseline) = get_memory_usage() else {
        println!("memory_{}: SKIPPED (memory tracking not available on this platform)", name);
        return;
    };
    
    println!("memory_{}: starting (baseline: {} KB, iterations: {}, limit: {} KB)", 
        name, baseline / 1024, iterations, max_growth_bytes / 1024);
    
    let check_interval = std::cmp::max(iterations / 10, 1);
    for i in 0..iterations {
        black_box(f());
        if i > 0 && i % check_interval == 0 {
            if let Some(current) = get_memory_usage() {
                let growth = current.saturating_sub(baseline);
                println!("memory_{}: {}% ({}/{}), growth: {} KB", 
                    name, (i * 100) / iterations, i, iterations, growth / 1024);
            }
        }
    }
    
    let final_mem = get_memory_usage().unwrap_or(baseline);
    let growth = final_mem.saturating_sub(baseline);
    
    println!("memory_{}: final growth: {} KB (limit: {} KB)", 
        name, growth / 1024, max_growth_bytes / 1024);
    
    if growth <= max_growth_bytes {
        println!("memory_{}: PASSED", name);
    } else {
        println!("memory_{}: FAILED (exceeded budget by {} KB)", 
            name, (growth - max_growth_bytes) / 1024);
        panic!(
            "memory_{}: grew by {} KB, exceeds limit of {} KB",
            name, growth / 1024, max_growth_bytes / 1024
        );
    }
}

/// Test fixture: sample JSON hook input
pub fn sample_hook_input(cmd: &str) -> String {
    format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":"{}"}}}}"#,
        cmd.replace('\\', r"\\").replace('"', r#"\""#)
    )
}

/// Test fixture: sample heredoc content
pub fn sample_heredoc(cmd: &str) -> String {
    format!("#!/bin/bash\nset -e\n{}
echo done", cmd)
}

//=============================================================================
// Infrastructure Validation Tests
//=============================================================================

/// Verify memory tracking works on this platform
#[test]
fn memory_tracking_sanity_check() {
    println!("memory_tracking_sanity_check: starting");
    
    let initial = get_memory_usage();
    if initial.is_none() {
        println!("memory_tracking_sanity_check: SKIPPED (not available on this platform)");
        return;
    }
    
    let initial = initial.unwrap();
    println!("memory_tracking_sanity_check: initial RSS = {} KB", initial / 1024);
    
    // Allocate 5MB and ensure pages are faulted in by writing non-zero values
    let mut data: Vec<u8> = Vec::with_capacity(5 * 1024 * 1024);
    for i in 0..5 * 1024 * 1024 {
        data.push((i % 255) as u8);
    }
    black_box(&data);
    
    let after_alloc = get_memory_usage().unwrap();
    let growth = after_alloc.saturating_sub(initial);
    
    println!("memory_tracking_sanity_check: after 5MB alloc, growth = {} KB", growth / 1024);
    
    // Should have grown by at least 4MB (allowing for some noise/optimization)
    assert!(
        growth >= 4 * 1024 * 1024,
        "Memory tracking seems broken: only {} KB growth after 5MB allocation",
        growth / 1024
    );
    
    println!("memory_tracking_sanity_check: PASSED");
}
