//! Shared command evaluator for hook mode and CLI.
//!
//! This module provides a unified evaluation entry point that can be used by both
//! the hook mode (stdin JSON) and CLI (`dcg test`) to ensure consistent behavior.
//!
//! # Architecture
//!
//! The evaluator performs the following steps in order:
//!
//! 1. **Config allow overrides** - Check if command matches an explicit allow pattern
//! 2. **Config block overrides** - Check if command matches an explicit block pattern
//! 3. **Quick rejection** - Skip expensive regex if no relevant keywords present
//! 4. **Command normalization** - Strip absolute paths from git/rm binaries
//! 5. **Safe patterns** - Whitelist check (legacy patterns in main.rs)
//! 6. **Destructive patterns** - Blacklist check (legacy patterns in main.rs)
//! 7. **Pack registry** - Check against enabled packs
//!
//! # Example
//!
//! ```ignore
//! use destructive_command_guard::config::Config;
//! use destructive_command_guard::evaluator::{evaluate_command, EvaluationDecision};
//!
//! let config = Config::load();
//! let enabled_keywords = vec!["git", "rm", "docker"];
//! let result = evaluate_command("git reset --hard", &config, &enabled_keywords);
//!
//! match result.decision {
//!     EvaluationDecision::Allow => println!("Command allowed"),
//!     EvaluationDecision::Deny => {
//!         if let Some(info) = &result.pattern_info {
//!             println!("Blocked by {}: {}", info.pack_id.as_deref().unwrap_or("legacy"), info.reason);
//!         }
//!     }
//! }
//! ```

use crate::config::Config;
use crate::packs::{REGISTRY, normalize_command, pack_aware_quick_reject};
use fancy_regex::Regex;
use std::collections::HashSet;

/// The decision made by the evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationDecision {
    /// Command is allowed to execute.
    Allow,
    /// Command is blocked from executing.
    Deny,
}

/// Information about the pattern that matched (for denials).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternMatch {
    /// The pack that blocked the command (None for legacy patterns or config overrides).
    pub pack_id: Option<String>,
    /// The name of the pattern that matched (if available).
    pub pattern_name: Option<String>,
    /// Human-readable reason for blocking.
    pub reason: String,
    /// Source of the match (for debugging/explain mode).
    pub source: MatchSource,
}

/// Source of a pattern match (for debugging and explain mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchSource {
    /// Matched a config override (allow or block).
    ConfigOverride,
    /// Matched a legacy pattern in main.rs.
    LegacyPattern,
    /// Matched a pattern from a pack.
    Pack,
}

/// Result of evaluating a command.
#[derive(Debug, Clone)]
pub struct EvaluationResult {
    /// The decision (Allow or Deny).
    pub decision: EvaluationDecision,
    /// Pattern match information (present when decision is Deny).
    pub pattern_info: Option<PatternMatch>,
}

impl EvaluationResult {
    /// Create an "allowed" result.
    #[inline]
    #[must_use]
    pub const fn allowed() -> Self {
        Self {
            decision: EvaluationDecision::Allow,
            pattern_info: None,
        }
    }

    /// Create a "denied" result from config override.
    #[inline]
    #[must_use]
    pub const fn denied_by_config(reason: String) -> Self {
        Self {
            decision: EvaluationDecision::Deny,
            pattern_info: Some(PatternMatch {
                pack_id: None,
                pattern_name: None,
                reason,
                source: MatchSource::ConfigOverride,
            }),
        }
    }

    /// Create a "denied" result from legacy pattern.
    #[inline]
    #[must_use]
    pub fn denied_by_legacy(reason: &str) -> Self {
        Self {
            decision: EvaluationDecision::Deny,
            pattern_info: Some(PatternMatch {
                pack_id: None,
                pattern_name: None,
                reason: reason.to_string(),
                source: MatchSource::LegacyPattern,
            }),
        }
    }

    /// Create a "denied" result from a pack.
    #[inline]
    #[must_use]
    pub fn denied_by_pack(pack_id: &str, reason: &str) -> Self {
        Self {
            decision: EvaluationDecision::Deny,
            pattern_info: Some(PatternMatch {
                pack_id: Some(pack_id.to_string()),
                pattern_name: None,
                reason: reason.to_string(),
                source: MatchSource::Pack,
            }),
        }
    }

    /// Create a "denied" result from a pack with pattern name.
    #[inline]
    #[must_use]
    pub fn denied_by_pack_pattern(pack_id: &str, pattern_name: &str, reason: &str) -> Self {
        Self {
            decision: EvaluationDecision::Deny,
            pattern_info: Some(PatternMatch {
                pack_id: Some(pack_id.to_string()),
                pattern_name: Some(pattern_name.to_string()),
                reason: reason.to_string(),
                source: MatchSource::Pack,
            }),
        }
    }

    /// Check if the command was allowed.
    #[inline]
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.decision == EvaluationDecision::Allow
    }

    /// Check if the command was denied.
    #[inline]
    #[must_use]
    pub fn is_denied(&self) -> bool {
        self.decision == EvaluationDecision::Deny
    }

    /// Get the reason for denial (if denied).
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.pattern_info.as_ref().map(|p| p.reason.as_str())
    }

    /// Get the pack ID that blocked (if denied by a pack).
    #[must_use]
    pub fn pack_id(&self) -> Option<&str> {
        self.pattern_info
            .as_ref()
            .and_then(|p| p.pack_id.as_deref())
    }
}

/// Evaluate a command against all patterns and packs.
///
/// This is the main entry point for command evaluation. It performs all checks
/// in the correct order and returns a structured result.
///
/// # Arguments
///
/// * `command` - The raw command string to evaluate
/// * `config` - Loaded configuration with overrides and pack settings
/// * `enabled_keywords` - Keywords from enabled packs for quick rejection
///
/// # Returns
///
/// An `EvaluationResult` indicating whether the command is allowed or denied,
/// with detailed pattern match information for denials.
///
/// # Performance
///
/// This function is optimized for the common case (allow):
/// - Quick rejection skips regex for 99%+ of commands
/// - Config overrides are checked before expensive pattern matching
/// - Short-circuits on first match
pub fn evaluate_command(
    command: &str,
    config: &Config,
    enabled_keywords: &[&str],
) -> EvaluationResult {
    // Empty commands are allowed (no-op)
    if command.is_empty() {
        return EvaluationResult::allowed();
    }

    // Step 1: Check explicit allow overrides first
    for allow in &config.overrides.allow {
        if allow.condition_met() {
            if let Ok(re) = Regex::new(allow.pattern()) {
                if re.is_match(command).unwrap_or(false) {
                    return EvaluationResult::allowed();
                }
            }
        }
    }

    // Step 2: Check explicit block overrides
    for block in &config.overrides.block {
        if let Ok(re) = Regex::new(&block.pattern) {
            if re.is_match(command).unwrap_or(false) {
                return EvaluationResult::denied_by_config(block.reason.clone());
            }
        }
    }

    // Step 3: Quick rejection - if no relevant keywords, allow immediately
    // This handles the 99%+ case where commands don't need pattern checking
    if pack_aware_quick_reject(command, enabled_keywords) {
        return EvaluationResult::allowed();
    }

    // Step 4: Normalize command (strip /usr/bin/git -> git, etc.)
    let normalized = normalize_command(command);

    // Step 5 & 6: Check legacy patterns (safe then destructive)
    // Note: These are currently in main.rs as SAFE_PATTERNS and DESTRUCTIVE_PATTERNS.
    // For now, we skip this step here since main.rs handles it.
    // TODO: Move legacy patterns here once git_safety_guard-99e.3.4 is implemented.

    // Step 7: Check against enabled packs from configuration
    let enabled_packs: HashSet<String> = config.enabled_pack_ids();
    let result = REGISTRY.check_command(&normalized, &enabled_packs);

    if result.blocked {
        let reason = result.reason.as_deref().unwrap_or("Blocked by pack");
        let pack_id = result.pack_id.as_deref().unwrap_or("unknown");
        return EvaluationResult::denied_by_pack(pack_id, reason);
    }

    // No pattern matched: default allow
    EvaluationResult::allowed()
}

/// Evaluate a command with legacy pattern support.
///
/// This version includes legacy `SAFE_PATTERNS` and `DESTRUCTIVE_PATTERNS` checking.
/// It's intended to be used by the main hook entrypoint until the legacy patterns
/// are migrated to the pack system (git_safety_guard-99e.3.4).
///
/// # Arguments
///
/// * `command` - The raw command string to evaluate
/// * `config` - Loaded configuration with overrides and pack settings
/// * `enabled_keywords` - Keywords from enabled packs for quick rejection
/// * `safe_patterns` - Legacy safe patterns (whitelist)
/// * `destructive_patterns` - Legacy destructive patterns (blacklist)
///
/// # Type Parameters
///
/// This function accepts any types that implement pattern matching:
/// * `S` - Safe pattern type with `is_match` method returning `Result<bool, _>`
/// * `D` - Destructive pattern type with `is_match` method and `reason` field
pub fn evaluate_command_with_legacy<S, D>(
    command: &str,
    config: &Config,
    enabled_keywords: &[&str],
    safe_patterns: &[S],
    destructive_patterns: &[D],
) -> EvaluationResult
where
    S: LegacySafePattern,
    D: LegacyDestructivePattern,
{
    // Empty commands are allowed (no-op)
    if command.is_empty() {
        return EvaluationResult::allowed();
    }

    // Step 1: Check explicit allow overrides first
    for allow in &config.overrides.allow {
        if allow.condition_met() {
            if let Ok(re) = Regex::new(allow.pattern()) {
                if re.is_match(command).unwrap_or(false) {
                    return EvaluationResult::allowed();
                }
            }
        }
    }

    // Step 2: Check explicit block overrides
    for block in &config.overrides.block {
        if let Ok(re) = Regex::new(&block.pattern) {
            if re.is_match(command).unwrap_or(false) {
                return EvaluationResult::denied_by_config(block.reason.clone());
            }
        }
    }

    // Step 3: Quick rejection - if no relevant keywords, allow immediately
    if pack_aware_quick_reject(command, enabled_keywords) {
        return EvaluationResult::allowed();
    }

    // Step 4: Normalize command (strip /usr/bin/git -> git, etc.)
    let normalized = normalize_command(command);

    // Step 5: Check legacy safe patterns (whitelist)
    for pattern in safe_patterns {
        if pattern.is_match(&normalized) {
            return EvaluationResult::allowed();
        }
    }

    // Step 6: Check legacy destructive patterns (blacklist)
    for pattern in destructive_patterns {
        if pattern.is_match(&normalized) {
            return EvaluationResult::denied_by_legacy(pattern.reason());
        }
    }

    // Step 7: Check against enabled packs from configuration
    let enabled_packs: HashSet<String> = config.enabled_pack_ids();
    let result = REGISTRY.check_command(&normalized, &enabled_packs);

    if result.blocked {
        let reason = result.reason.as_deref().unwrap_or("Blocked by pack");
        let pack_id = result.pack_id.as_deref().unwrap_or("unknown");
        return EvaluationResult::denied_by_pack(pack_id, reason);
    }

    // No pattern matched: default allow
    EvaluationResult::allowed()
}

/// Trait for legacy safe patterns.
pub trait LegacySafePattern {
    /// Check if the pattern matches the command.
    fn is_match(&self, cmd: &str) -> bool;
}

/// Trait for legacy destructive patterns.
pub trait LegacyDestructivePattern {
    /// Check if the pattern matches the command.
    fn is_match(&self, cmd: &str) -> bool;
    /// Get the reason for blocking.
    fn reason(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> Config {
        Config::default()
    }

    #[test]
    fn test_empty_command_allowed() {
        let config = default_config();
        let result = evaluate_command("", &config, &[]);
        assert!(result.is_allowed());
        assert!(result.pattern_info.is_none());
    }

    #[test]
    fn test_safe_command_allowed() {
        let config = default_config();
        let result = evaluate_command("ls -la", &config, &["git", "rm"]);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_result_helper_methods() {
        let allowed = EvaluationResult::allowed();
        assert!(allowed.is_allowed());
        assert!(!allowed.is_denied());
        assert!(allowed.reason().is_none());
        assert!(allowed.pack_id().is_none());

        let denied = EvaluationResult::denied_by_pack("test.pack", "test reason");
        assert!(!denied.is_allowed());
        assert!(denied.is_denied());
        assert_eq!(denied.reason(), Some("test reason"));
        assert_eq!(denied.pack_id(), Some("test.pack"));
    }

    #[test]
    fn test_denied_by_config() {
        let denied = EvaluationResult::denied_by_config("config block".to_string());
        assert!(denied.is_denied());
        assert_eq!(denied.reason(), Some("config block"));
        assert!(denied.pack_id().is_none());
        assert_eq!(
            denied.pattern_info.as_ref().unwrap().source,
            MatchSource::ConfigOverride
        );
    }

    #[test]
    fn test_denied_by_legacy() {
        let denied = EvaluationResult::denied_by_legacy("legacy reason");
        assert!(denied.is_denied());
        assert_eq!(denied.reason(), Some("legacy reason"));
        assert!(denied.pack_id().is_none());
        assert_eq!(
            denied.pattern_info.as_ref().unwrap().source,
            MatchSource::LegacyPattern
        );
    }

    #[test]
    fn test_denied_by_pack_pattern() {
        let denied = EvaluationResult::denied_by_pack_pattern("core.git", "reset-hard", "test");
        assert!(denied.is_denied());
        assert_eq!(denied.pack_id(), Some("core.git"));
        assert_eq!(
            denied.pattern_info.as_ref().unwrap().pattern_name,
            Some("reset-hard".to_string())
        );
    }

    #[test]
    fn test_quick_reject_skips_patterns() {
        let config = default_config();
        // Command with no relevant keywords should be quickly allowed
        let result = evaluate_command("cargo build --release", &config, &["git", "rm"]);
        assert!(result.is_allowed());

        // Even with more keywords
        let result = evaluate_command("npm install", &config, &["git", "rm", "docker", "kubectl"]);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_evaluation_decision_equality() {
        assert_eq!(EvaluationDecision::Allow, EvaluationDecision::Allow);
        assert_eq!(EvaluationDecision::Deny, EvaluationDecision::Deny);
        assert_ne!(EvaluationDecision::Allow, EvaluationDecision::Deny);
    }

    #[test]
    fn test_match_source_equality() {
        assert_eq!(MatchSource::ConfigOverride, MatchSource::ConfigOverride);
        assert_eq!(MatchSource::LegacyPattern, MatchSource::LegacyPattern);
        assert_eq!(MatchSource::Pack, MatchSource::Pack);
        assert_ne!(MatchSource::ConfigOverride, MatchSource::Pack);
    }

    // =========================================================================
    // Hook/CLI Evaluator Parity Tests (git_safety_guard-99e.3.5)
    // =========================================================================
    //
    // These tests verify that evaluate_command and evaluate_command_with_legacy
    // produce identical decisions for pack-based patterns, ensuring hook mode
    // and CLI mode agree once legacy patterns are retired.

    /// Helper struct for legacy safe pattern testing.
    struct MockSafePattern {
        regex: Regex,
    }

    impl LegacySafePattern for MockSafePattern {
        fn is_match(&self, cmd: &str) -> bool {
            self.regex.is_match(cmd).unwrap_or(false)
        }
    }

    /// Helper struct for legacy destructive pattern testing.
    struct MockDestructivePattern {
        regex: Regex,
        reason: String,
    }

    impl LegacyDestructivePattern for MockDestructivePattern {
        fn is_match(&self, cmd: &str) -> bool {
            self.regex.is_match(cmd).unwrap_or(false)
        }
        fn reason(&self) -> &str {
            &self.reason
        }
    }

    /// Table-driven parity test: commands that should be ALLOWED by both paths.
    #[test]
    fn parity_allowed_commands() {
        let config = default_config();
        let keywords = &["git", "rm", "docker", "kubectl"];
        let safe_patterns: Vec<MockSafePattern> = vec![];
        let destructive_patterns: Vec<MockDestructivePattern> = vec![];

        let test_cases = [
            // Non-relevant commands (quick-rejected)
            "ls -la",
            "cargo build --release",
            "npm install",
            "echo hello",
            "cat /etc/passwd",
            // Empty command
            "",
        ];

        for cmd in test_cases {
            let result1 = evaluate_command(cmd, &config, keywords);
            let result2 = evaluate_command_with_legacy(
                cmd,
                &config,
                keywords,
                &safe_patterns,
                &destructive_patterns,
            );

            assert_eq!(
                result1.decision, result2.decision,
                "Parity mismatch for allowed command: {cmd:?}"
            );
            assert!(
                result1.is_allowed(),
                "Expected ALLOWED for {cmd:?}, got DENIED"
            );
        }
    }

    /// Table-driven parity test: commands blocked by pack patterns.
    #[test]
    fn parity_pack_blocked_commands() {
        // Create a config that enables the docker pack
        let mut config = default_config();
        config.packs.enabled.push("containers.docker".to_string());

        let enabled_packs = config.enabled_pack_ids();
        let keywords_vec = crate::packs::REGISTRY.collect_enabled_keywords(&enabled_packs);
        let keywords: Vec<&str> = keywords_vec.clone();

        let safe_patterns: Vec<MockSafePattern> = vec![];
        let destructive_patterns: Vec<MockDestructivePattern> = vec![];

        // Commands that should be blocked by docker pack
        let blocked_commands = ["docker system prune", "docker system prune -a"];

        for cmd in blocked_commands {
            let result1 = evaluate_command(cmd, &config, &keywords);
            let result2 = evaluate_command_with_legacy(
                cmd,
                &config,
                &keywords,
                &safe_patterns,
                &destructive_patterns,
            );

            assert_eq!(
                result1.decision, result2.decision,
                "Parity mismatch for pack-blocked command: {cmd:?}"
            );
            assert!(
                result1.is_denied(),
                "Expected DENIED for {cmd:?}, got ALLOWED"
            );
            assert_eq!(
                result1.pack_id(),
                result2.pack_id(),
                "Pack ID mismatch for {cmd:?}"
            );
        }
    }

    /// Parity test: config allow overrides work in both paths.
    #[test]
    fn parity_config_allow_override() {
        use crate::config::AllowOverride;

        let mut config = default_config();
        config.packs.enabled.push("containers.docker".to_string());
        // Add an allow override that permits docker prune
        config.overrides.allow.push(AllowOverride::Simple(
            "docker system prune".to_string(),
        ));

        let enabled_packs = config.enabled_pack_ids();
        let keywords_vec = crate::packs::REGISTRY.collect_enabled_keywords(&enabled_packs);
        let keywords: Vec<&str> = keywords_vec.clone();

        let safe_patterns: Vec<MockSafePattern> = vec![];
        let destructive_patterns: Vec<MockDestructivePattern> = vec![];

        let cmd = "docker system prune";

        let result1 = evaluate_command(cmd, &config, &keywords);
        let result2 = evaluate_command_with_legacy(
            cmd,
            &config,
            &keywords,
            &safe_patterns,
            &destructive_patterns,
        );

        assert_eq!(
            result1.decision, result2.decision,
            "Parity mismatch for config allow override"
        );
        assert!(
            result1.is_allowed(),
            "Config allow override should permit docker prune"
        );
    }

    /// Parity test: config block overrides work in both paths.
    #[test]
    fn parity_config_block_override() {
        use crate::config::BlockOverride;

        let mut config = default_config();
        // Add a block override that blocks a normally-safe command
        config.overrides.block.push(BlockOverride {
            pattern: "ls.*secret".to_string(),
            reason: "Blocked by config".to_string(),
        });

        let keywords = &["ls"]; // Need ls keyword to not quick-reject

        let safe_patterns: Vec<MockSafePattern> = vec![];
        let destructive_patterns: Vec<MockDestructivePattern> = vec![];

        let cmd = "ls /secret/files";

        let result1 = evaluate_command(cmd, &config, keywords);
        let result2 = evaluate_command_with_legacy(
            cmd,
            &config,
            keywords,
            &safe_patterns,
            &destructive_patterns,
        );

        assert_eq!(
            result1.decision, result2.decision,
            "Parity mismatch for config block override"
        );
        assert!(
            result1.is_denied(),
            "Config block override should deny ls /secret/files"
        );
        assert_eq!(
            result1.pattern_info.as_ref().unwrap().source,
            MatchSource::ConfigOverride
        );
    }

    /// Verify legacy patterns cause divergence (expected until legacy is retired).
    /// This test documents the current behavior and will help catch when we retire legacy.
    #[test]
    fn legacy_patterns_cause_expected_divergence() {
        let config = default_config();
        let keywords = &["test"];

        // Create a legacy destructive pattern that blocks "test dangerous"
        let safe_patterns: Vec<MockSafePattern> = vec![];
        let destructive_patterns = vec![MockDestructivePattern {
            regex: Regex::new("test dangerous").unwrap(),
            reason: "Legacy block".to_string(),
        }];

        let cmd = "test dangerous command";

        let result1 = evaluate_command(cmd, &config, keywords);
        let result2 = evaluate_command_with_legacy(
            cmd,
            &config,
            keywords,
            &safe_patterns,
            &destructive_patterns,
        );

        // evaluate_command (CLI path) allows it (no pack match)
        assert!(result1.is_allowed(), "evaluate_command should allow (no pack match)");

        // evaluate_command_with_legacy (hook path) blocks it (legacy match)
        assert!(
            result2.is_denied(),
            "evaluate_command_with_legacy should deny (legacy match)"
        );
        assert_eq!(
            result2.pattern_info.as_ref().unwrap().source,
            MatchSource::LegacyPattern
        );

        // This divergence is expected and will go away when legacy patterns are retired
    }

    /// Verify normalization is applied consistently in both paths.
    #[test]
    fn parity_command_normalization() {
        let mut config = default_config();
        config.packs.enabled.push("containers.docker".to_string());

        let enabled_packs = config.enabled_pack_ids();
        let keywords_vec = crate::packs::REGISTRY.collect_enabled_keywords(&enabled_packs);
        let keywords: Vec<&str> = keywords_vec.clone();

        let safe_patterns: Vec<MockSafePattern> = vec![];
        let destructive_patterns: Vec<MockDestructivePattern> = vec![];

        // Command with absolute path (should be normalized)
        let cmd = "/usr/bin/docker system prune";

        let result1 = evaluate_command(cmd, &config, &keywords);
        let result2 = evaluate_command_with_legacy(
            cmd,
            &config,
            &keywords,
            &safe_patterns,
            &destructive_patterns,
        );

        assert_eq!(
            result1.decision, result2.decision,
            "Parity mismatch for normalized command"
        );
        // Should be blocked after normalization strips /usr/bin/
        assert!(
            result1.is_denied(),
            "Normalized docker prune should be blocked"
        );
    }
}
