//! Regression corpus test harness with full isomorphism verification.
//!
//! This module loads test cases from `tests/corpus/` and runs them through the evaluator,
//! comparing ALL evaluation fields to ensure refactors don't change behavior.
//!
//! # Corpus Structure
//!
//! ```text
//! tests/corpus/
//!   true_positives/   # Commands that MUST be blocked (deny)
//!   false_positives/  # Commands that MUST be allowed (allow)
//!   bypass_attempts/  # Obfuscated dangerous commands (deny)
//!   edge_cases/       # Commands that must not crash (any decision ok)
//! ```
//!
//! # Test Case Format (TOML)
//!
//! ```toml
//! [[case]]
//! description = "git reset --hard blocks correctly"
//! command = "git reset --hard"
//! expected = "deny"  # or "allow"
//! rule_id = "core.git:reset-hard"  # optional
//!
//! [case.log]  # Optional: detailed field verification
//! decision = "deny"
//! mode = "deny"
//! pack_id = "core.git"
//! pattern_name = "reset-hard"
//! rule_id = "core.git:reset-hard"
//! reason_contains = "destroys uncommitted"
//! ```
//!
//! # Isomorphism Guarantee
//!
//! When `[case.log]` is present, the test verifies ALL fields match exactly:
//! - decision (allow/deny)
//! - effective_mode (deny/warn/log)
//! - pack_id
//! - pattern_name
//! - rule_id (pack:pattern format)
//! - reason_contains (substring match)
//! - allowlist_layer (project/user/system)
//!
//! This ensures that performance optimizations and refactors don't accidentally
//! change evaluation semantics.
//!
//! # Running
//!
//! ```bash
//! cargo test --test regression_corpus
//! ```

use std::path::Path;

use destructive_command_guard::packs::test_helpers::{
    CorpusCategory, CorpusTestCase, load_corpus_dir, verify_corpus_case,
};

/// Load all corpus test cases from the standard directory.
fn load_all_cases() -> Vec<(CorpusCategory, String, CorpusTestCase)> {
    let corpus_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    load_corpus_dir(&corpus_dir).expect("Failed to load corpus directory")
}

/// Run verification on cases matching a specific category.
fn run_category_tests(category: CorpusCategory) -> (usize, Vec<String>) {
    let all_cases = load_all_cases();
    let category_cases: Vec<_> = all_cases
        .iter()
        .filter(|(cat, _, _)| *cat == category)
        .collect();

    let total = category_cases.len();
    let mut failures = Vec::new();

    for (cat, file, case) in category_cases {
        if let Err(msg) = verify_corpus_case(case, *cat) {
            failures.push(format!("[{file}] {msg}"));
        }
    }

    (total, failures)
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn corpus_true_positives_isomorphism() {
    let (total, failures) = run_category_tests(CorpusCategory::TruePositives);

    if !failures.is_empty() {
        let mut msg = format!(
            "\n{}/{} true positive test(s) failed:\n",
            failures.len(),
            total
        );
        for failure in &failures {
            msg.push_str(&format!("  {failure}\n"));
        }
        panic!("{msg}");
    }

    println!("All {total} true positive tests passed with full isomorphism check");
}

#[test]
fn corpus_false_positives_isomorphism() {
    let (total, failures) = run_category_tests(CorpusCategory::FalsePositives);

    if !failures.is_empty() {
        let mut msg = format!(
            "\n{}/{} false positive test(s) failed:\n",
            failures.len(),
            total
        );
        for failure in &failures {
            msg.push_str(&format!("  {failure}\n"));
        }
        panic!("{msg}");
    }

    println!("All {total} false positive tests passed with full isomorphism check");
}

#[test]
fn corpus_bypass_attempts_isomorphism() {
    let (total, failures) = run_category_tests(CorpusCategory::BypassAttempts);

    if !failures.is_empty() {
        let mut msg = format!(
            "\n{}/{} bypass attempt test(s) failed:\n",
            failures.len(),
            total
        );
        for failure in &failures {
            msg.push_str(&format!("  {failure}\n"));
        }
        panic!("{msg}");
    }

    println!("All {total} bypass attempt tests passed with full isomorphism check");
}

#[test]
fn corpus_edge_cases_isomorphism() {
    let (total, failures) = run_category_tests(CorpusCategory::EdgeCases);

    // Edge cases should still pass verification (any decision is acceptable,
    // but if they have [case.log] sections, those should match)
    if !failures.is_empty() {
        let mut msg = format!("\n{}/{} edge case test(s) failed:\n", failures.len(), total);
        for failure in &failures {
            msg.push_str(&format!("  {failure}\n"));
        }
        panic!("{msg}");
    }

    println!("All {total} edge case tests passed with full isomorphism check");
}

#[test]
fn corpus_full_summary() {
    let all_cases = load_all_cases();
    let mut passed = 0;
    let mut failed = 0;
    let mut failures = Vec::new();

    for (category, file, case) in &all_cases {
        match verify_corpus_case(case, *category) {
            Ok(()) => passed += 1,
            Err(msg) => {
                failed += 1;
                failures.push(format!("[{file}] {msg}"));
            }
        }
    }

    println!("\n=== Corpus Isomorphism Test Summary ===");
    println!(
        "Total: {} tests ({} passed, {} failed)",
        all_cases.len(),
        passed,
        failed
    );

    // Count by category
    let mut by_category: std::collections::HashMap<CorpusCategory, (usize, usize)> =
        std::collections::HashMap::new();
    for (category, _file, case) in &all_cases {
        let entry = by_category.entry(*category).or_insert((0, 0));
        entry.0 += 1;
        if verify_corpus_case(case, *category).is_ok() {
            entry.1 += 1;
        }
    }

    println!();
    for (category, (total, cat_passed)) in by_category {
        let status = if cat_passed == total { "OK" } else { "FAIL" };
        println!("  {category:?}: {cat_passed}/{total} [{status}]");
    }

    if !failures.is_empty() {
        println!("\nFailures (with reproduction commands):");
        for failure in &failures {
            println!("  {failure}");
        }
        panic!("\n{} corpus test(s) failed", failures.len());
    }
}
