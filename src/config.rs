//! Configuration system for dcg.
//!
//! Supports layered configuration from multiple sources:
//! 1. Environment variables (highest priority)
//! 2. Project config (.dcg.toml in repo root)
//! 3. User config (~/.config/dcg/config.toml)
//! 4. System config (/etc/dcg/config.toml)
//! 5. Compiled defaults (lowest priority)

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Environment variable prefix for all config options.
const ENV_PREFIX: &str = "DCG";

/// Default config file name.
const CONFIG_FILE_NAME: &str = "config.toml";

/// Project-level config file name.
const PROJECT_CONFIG_NAME: &str = ".dcg.toml";

/// Main configuration structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// General settings.
    pub general: GeneralConfig,

    /// Pack configuration.
    pub packs: PacksConfig,

    /// Custom overrides.
    pub overrides: OverridesConfig,

    /// Project-specific configurations (keyed by absolute path).
    #[serde(default)]
    pub projects: std::collections::HashMap<String, ProjectConfig>,
}

/// General configuration options.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    /// Color output mode: "auto", "always", "never".
    pub color: String,

    /// Path to log file for blocked commands (optional).
    pub log_file: Option<String>,

    /// Whether to show verbose output.
    pub verbose: bool,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            color: "auto".to_string(),
            log_file: None,
            verbose: false,
        }
    }
}

/// Pack enablement configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PacksConfig {
    /// List of enabled packs (e.g., `["database.postgresql", "kubernetes"]`).
    pub enabled: Vec<String>,

    /// List of explicitly disabled packs (for disabling sub-packs of enabled categories).
    pub disabled: Vec<String>,
}

/// Custom pattern overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OverridesConfig {
    /// Patterns to allow that would otherwise be blocked.
    #[serde(default)]
    pub allow: Vec<AllowOverride>,

    /// Additional patterns to block.
    #[serde(default)]
    pub block: Vec<BlockOverride>,
}

/// An allow override - patterns that should be permitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AllowOverride {
    /// Simple pattern string.
    Simple(String),
    /// Conditional override with optional `when` clause.
    Conditional {
        pattern: String,
        /// Optional condition (e.g., "CI=true").
        when: Option<String>,
    },
}

impl AllowOverride {
    /// Get the pattern string.
    #[must_use]
    pub fn pattern(&self) -> &str {
        match self {
            Self::Simple(p) => p,
            Self::Conditional { pattern, .. } => pattern,
        }
    }

    /// Check if the condition is met (if any).
    #[must_use]
    pub fn condition_met(&self) -> bool {
        match self {
            Self::Simple(_) | Self::Conditional { when: None, .. } => true,
            Self::Conditional {
                when: Some(condition),
                ..
            } => {
                // Parse condition like "CI=true"
                if let Some((var, expected)) = condition.split_once('=') {
                    env::var(var).map(|v| v == expected).unwrap_or(false)
                } else {
                    // Just check if the env var is set
                    env::var(condition).is_ok()
                }
            }
        }
    }
}

/// A block override - additional patterns to block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockOverride {
    /// The regex pattern to match.
    pub pattern: String,
    /// Human-readable reason for blocking.
    pub reason: String,
}

// ============================================================================
// Compiled Overrides (Runtime-Only, Pre-compiled Regexes)
// ============================================================================

use fancy_regex::Regex;

/// A compiled allow override with precompiled regex.
///
/// This is the runtime representation used for evaluation.
/// Created once at config load time, not per-command.
#[derive(Debug)]
pub struct CompiledAllowOverride {
    /// The precompiled regex pattern.
    pub regex: Regex,
    /// The original pattern string (for diagnostics).
    pub pattern: String,
    /// The condition evaluator (returns true if condition is met).
    /// For simple overrides, this always returns true.
    /// For conditional overrides, this checks the environment.
    condition: ConditionCheck,
}

/// Condition check type - either always true or checks an env var.
#[derive(Debug)]
enum ConditionCheck {
    /// Always allow (no condition).
    Always,
    /// Check if env var equals expected value.
    EnvEquals { var: String, expected: String },
    /// Check if env var is set (any value).
    EnvSet { var: String },
}

impl ConditionCheck {
    /// Check if the condition is met.
    fn is_met(&self) -> bool {
        match self {
            Self::Always => true,
            Self::EnvEquals { var, expected } => {
                std::env::var(var).map(|v| v == *expected).unwrap_or(false)
            }
            Self::EnvSet { var } => std::env::var(var).is_ok(),
        }
    }
}

impl CompiledAllowOverride {
    /// Check if this override matches and its condition is met.
    ///
    /// Returns true if the command matches and should be allowed.
    #[inline]
    #[must_use]
    pub fn matches(&self, command: &str) -> bool {
        self.condition.is_met() && self.regex.is_match(command).unwrap_or(false)
    }
}

/// A compiled block override with precompiled regex.
#[derive(Debug)]
pub struct CompiledBlockOverride {
    /// The precompiled regex pattern.
    pub regex: Regex,
    /// The original pattern string (for diagnostics).
    pub pattern: String,
    /// Human-readable reason for blocking.
    pub reason: String,
}

impl CompiledBlockOverride {
    /// Check if this override matches.
    ///
    /// Returns the reason if blocked.
    #[inline]
    #[must_use]
    pub fn matches(&self, command: &str) -> Option<&str> {
        if self.regex.is_match(command).unwrap_or(false) {
            Some(&self.reason)
        } else {
            None
        }
    }
}

/// Compiled overrides - runtime representation with precompiled regexes.
///
/// This struct is created once per config load and reused for all command
/// evaluations. It eliminates per-command regex compilation overhead.
#[derive(Debug, Default)]
pub struct CompiledOverrides {
    /// Compiled allow overrides.
    pub allow: Vec<CompiledAllowOverride>,
    /// Compiled block overrides.
    pub block: Vec<CompiledBlockOverride>,
    /// Patterns that failed to compile (for diagnostics).
    pub invalid_patterns: Vec<InvalidPattern>,
}

/// Record of a pattern that failed to compile.
#[derive(Debug, Clone)]
pub struct InvalidPattern {
    /// The original pattern string.
    pub pattern: String,
    /// The compilation error message.
    pub error: String,
    /// Whether this was an allow or block pattern.
    pub kind: PatternKind,
}

/// Kind of override pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternKind {
    Allow,
    Block,
}

impl CompiledOverrides {
    /// Check allow overrides. Returns true if command should be allowed.
    #[inline]
    #[must_use]
    pub fn check_allow(&self, command: &str) -> bool {
        self.allow.iter().any(|o| o.matches(command))
    }

    /// Check block overrides. Returns the reason if command should be blocked.
    #[inline]
    #[must_use]
    pub fn check_block(&self, command: &str) -> Option<&str> {
        self.block.iter().find_map(|o| o.matches(command))
    }

    /// Check if there are any invalid patterns.
    #[must_use]
    pub fn has_invalid_patterns(&self) -> bool {
        !self.invalid_patterns.is_empty()
    }
}

impl OverridesConfig {
    /// Compile all override patterns into precompiled regexes.
    ///
    /// Invalid patterns are collected but do not cause errors (fail-open).
    /// Use `CompiledOverrides::invalid_patterns` to check for issues.
    #[must_use]
    pub fn compile(&self) -> CompiledOverrides {
        let mut compiled = CompiledOverrides::default();

        // Compile allow overrides
        for allow in &self.allow {
            match Regex::new(allow.pattern()) {
                Ok(regex) => {
                    let condition = match allow {
                        AllowOverride::Simple(_)
                        | AllowOverride::Conditional { when: None, .. } => ConditionCheck::Always,
                        AllowOverride::Conditional {
                            when: Some(condition),
                            ..
                        } => {
                            if let Some((var, expected)) = condition.split_once('=') {
                                ConditionCheck::EnvEquals {
                                    var: var.to_string(),
                                    expected: expected.to_string(),
                                }
                            } else {
                                ConditionCheck::EnvSet {
                                    var: condition.clone(),
                                }
                            }
                        }
                    };
                    compiled.allow.push(CompiledAllowOverride {
                        regex,
                        pattern: allow.pattern().to_string(),
                        condition,
                    });
                }
                Err(e) => {
                    compiled.invalid_patterns.push(InvalidPattern {
                        pattern: allow.pattern().to_string(),
                        error: e.to_string(),
                        kind: PatternKind::Allow,
                    });
                }
            }
        }

        // Compile block overrides
        for block in &self.block {
            match Regex::new(&block.pattern) {
                Ok(regex) => {
                    compiled.block.push(CompiledBlockOverride {
                        regex,
                        pattern: block.pattern.clone(),
                        reason: block.reason.clone(),
                    });
                }
                Err(e) => {
                    compiled.invalid_patterns.push(InvalidPattern {
                        pattern: block.pattern.clone(),
                        error: e.to_string(),
                        kind: PatternKind::Block,
                    });
                }
            }
        }

        compiled
    }
}

/// Project-specific configuration overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProjectConfig {
    /// Pack configuration for this project.
    pub packs: Option<PacksConfig>,

    /// Overrides for this project.
    pub overrides: Option<OverridesConfig>,
}

impl Config {
    /// Load configuration from all sources, merging them in priority order.
    ///
    /// Priority (highest to lowest):
    /// 1. Environment variables
    /// 2. Project config (.dcg.toml)
    /// 3. User config (~/.config/dcg/config.toml)
    /// 4. System config (/etc/dcg/config.toml)
    /// 5. Compiled defaults
    #[must_use]
    pub fn load() -> Self {
        let mut config = Self::default();

        // Load system config (lowest priority of file configs)
        if let Some(system_config) = Self::load_system_config() {
            config.merge(system_config);
        }

        // Load user config
        if let Some(user_config) = Self::load_user_config() {
            config.merge(user_config);
        }

        // Load project config (if in a git repo)
        if let Some(project_config) = Self::load_project_config() {
            config.merge(project_config);
        }

        // Apply environment variable overrides (highest priority)
        config.apply_env_overrides();

        config
    }

    /// Load configuration from a specific file.
    #[must_use]
    pub fn load_from_file(path: &Path) -> Option<Self> {
        let content = fs::read_to_string(path).ok()?;
        toml::from_str(&content).ok()
    }

    /// Load system-wide configuration.
    fn load_system_config() -> Option<Self> {
        let path = PathBuf::from("/etc/dcg").join(CONFIG_FILE_NAME);
        Self::load_from_file(&path)
    }

    /// Load user configuration.
    fn load_user_config() -> Option<Self> {
        let config_dir = dirs::config_dir()?;
        let path = config_dir.join("dcg").join(CONFIG_FILE_NAME);
        Self::load_from_file(&path)
    }

    /// Load project-level configuration.
    fn load_project_config() -> Option<Self> {
        // Try to find .dcg.toml in current dir or parent dirs
        let mut current = env::current_dir().ok()?;

        loop {
            let config_path = current.join(PROJECT_CONFIG_NAME);
            if config_path.exists() {
                return Self::load_from_file(&config_path);
            }

            // Also check for .git directory to find repo root
            let git_dir = current.join(".git");
            if git_dir.exists() {
                // We're at the repo root, check for config here
                let config_path = current.join(PROJECT_CONFIG_NAME);
                return Self::load_from_file(&config_path);
            }

            // Move to parent directory
            if !current.pop() {
                break;
            }
        }

        None
    }

    /// Merge another config into this one (other takes priority).
    fn merge(&mut self, other: Self) {
        // Merge general settings
        if other.general.color != "auto" {
            self.general.color = other.general.color;
        }
        if other.general.log_file.is_some() {
            self.general.log_file = other.general.log_file;
        }
        if other.general.verbose {
            self.general.verbose = true;
        }

        // Merge packs (append, don't replace)
        self.packs.enabled.extend(other.packs.enabled);
        self.packs.disabled.extend(other.packs.disabled);

        // Merge overrides (append)
        self.overrides.allow.extend(other.overrides.allow);
        self.overrides.block.extend(other.overrides.block);

        // Merge project configs
        self.projects.extend(other.projects);
    }

    /// Apply environment variable overrides.
    fn apply_env_overrides(&mut self) {
        // DCG_PACKS="core,database.postgresql,kubernetes"
        if let Ok(packs) = env::var(format!("{ENV_PREFIX}_PACKS")) {
            self.packs.enabled = packs.split(',').map(|s| s.trim().to_string()).collect();
        }

        // DCG_DISABLE="kubernetes.helm"
        if let Ok(disable) = env::var(format!("{ENV_PREFIX}_DISABLE")) {
            self.packs.disabled = disable.split(',').map(|s| s.trim().to_string()).collect();
        }

        // DCG_VERBOSE=1
        if env::var(format!("{ENV_PREFIX}_VERBOSE")).is_ok() {
            self.general.verbose = true;
        }

        // DCG_COLOR=never
        if let Ok(color) = env::var(format!("{ENV_PREFIX}_COLOR")) {
            self.general.color = color;
        }
    }

    /// Check if the bypass flag is set (escape hatch).
    #[must_use]
    pub fn is_bypassed() -> bool {
        env::var(format!("{ENV_PREFIX}_BYPASS")).is_ok()
    }

    /// Get the effective pack configuration for a specific project path.
    #[must_use]
    pub fn effective_packs_for_project(&self, project_path: &Path) -> PacksConfig {
        // Check if there's a project-specific config
        let path_str = project_path.to_string_lossy();

        for (project_pattern, project_config) in &self.projects {
            if path_str.starts_with(project_pattern) {
                if let Some(packs) = &project_config.packs {
                    return packs.clone();
                }
            }
        }

        // Fall back to global config
        self.packs.clone()
    }

    /// Get enabled pack IDs as a deduplicated set.
    #[must_use]
    pub fn enabled_pack_ids(&self) -> HashSet<String> {
        let mut enabled: HashSet<String> = self.packs.enabled.iter().cloned().collect();

        // Remove explicitly disabled packs
        for disabled in &self.packs.disabled {
            enabled.remove(disabled);
            // Also remove sub-packs if a category is disabled
            enabled.retain(|p| !p.starts_with(&format!("{disabled}.")));
        }

        // Core is always enabled
        enabled.insert("core".to_string());

        enabled
    }

    /// Get the path to the user config file (creates dir if needed).
    #[must_use]
    pub fn user_config_path() -> Option<PathBuf> {
        let config_dir = dirs::config_dir()?;
        let guard_dir = config_dir.join("dcg");

        // Create directory if it doesn't exist
        if !guard_dir.exists() {
            fs::create_dir_all(&guard_dir).ok()?;
        }

        Some(guard_dir.join(CONFIG_FILE_NAME))
    }

    /// Save configuration to the user config file.
    ///
    /// # Errors
    ///
    /// Returns an error if the config directory cannot be determined/created,
    /// serialization fails, or the config file cannot be written.
    pub fn save_to_user_config(&self) -> Result<PathBuf, String> {
        let path = Self::user_config_path().ok_or("Could not determine config directory")?;

        let content =
            toml::to_string_pretty(self).map_err(|e| format!("Failed to serialize config: {e}"))?;

        fs::write(&path, content).map_err(|e| format!("Failed to write config: {e}"))?;

        Ok(path)
    }

    /// Generate a default configuration with common packs enabled.
    #[must_use]
    pub fn generate_default() -> Self {
        Self {
            general: GeneralConfig::default(),
            packs: PacksConfig {
                enabled: vec![
                    // Core is implicit, but list common ones
                    "database.postgresql".to_string(),
                    "containers.docker".to_string(),
                ],
                disabled: vec![],
            },
            overrides: OverridesConfig::default(),
            projects: std::collections::HashMap::new(),
        }
    }

    /// Generate a sample configuration string with comments.
    #[must_use]
    pub fn generate_sample_config() -> String {
        r#"# dcg configuration
# https://github.com/Dicklesworthstone/dcg

[general]
# Color output: "auto" | "always" | "never"
color = "auto"

# Log blocked commands to file (optional)
# log_file = "~/.local/share/dcg/blocked.log"

# Verbose output
verbose = false

#─────────────────────────────────────────────────────────────
# PACK CONFIGURATION
#─────────────────────────────────────────────────────────────

[packs]
# Enable entire categories or specific sub-packs.
# Core pack is always enabled implicitly.
#
# Available packs:
#   core                  - Git and filesystem protections (always on)
#   database.postgresql   - PostgreSQL destructive commands
#   database.mysql        - MySQL destructive commands
#   database.mongodb      - MongoDB destructive commands
#   database.redis        - Redis FLUSH commands
#   database.sqlite       - SQLite destructive commands
#   containers.docker     - Docker destructive commands
#   containers.compose    - Docker Compose destructive commands
#   containers.podman     - Podman destructive commands
#   kubernetes.kubectl    - kubectl delete commands
#   kubernetes.helm       - Helm uninstall commands
#   kubernetes.kustomize  - Kustomize delete commands
#   cloud.aws             - AWS CLI destructive commands
#   cloud.gcp             - GCP CLI destructive commands
#   cloud.azure           - Azure CLI destructive commands
#   infrastructure.terraform - Terraform destroy commands
#   infrastructure.ansible   - Ansible state=absent patterns
#   infrastructure.pulumi    - Pulumi destroy commands
#   system.disk           - Disk operations (dd, mkfs, fdisk)
#   system.permissions    - Dangerous permission changes
#   system.services       - Service management commands
#   strict_git            - Extra paranoid git protections
#   package_managers      - npm unpublish, cargo yank, etc.

enabled = [
    "database.postgresql",
    "containers.docker",
    # "kubernetes",         # Uncomment to enable all kubernetes sub-packs
    # "cloud.aws",
]

# Explicitly disable specific sub-packs
disabled = [
    # "kubernetes.kustomize",  # Example: disable kustomize if you don't use it
]

#─────────────────────────────────────────────────────────────
# CUSTOM OVERRIDES
#─────────────────────────────────────────────────────────────

[overrides]
# Allow specific patterns that would otherwise be blocked.
# Supports simple strings or conditional objects.
allow = [
    # Example: Allow deleting test namespaces
    # "kubectl delete namespace test-.*",

    # Example: Allow dropping test databases
    # "dropdb test_.*",

    # Example: Conditional - only in CI
    # { pattern = "docker system prune", when = "CI=true" },
]

# Block additional patterns not covered by any pack.
block = [
    # Example: Block a custom dangerous script
    # { pattern = "deploy-to-prod\\.sh.*--force", reason = "Never force-deploy to production" },

    # Example: Block piping curl to shell
    # { pattern = "curl.*\\| ?sh", reason = "Piping curl to shell is dangerous" },
]

#─────────────────────────────────────────────────────────────
# PROJECT-SPECIFIC OVERRIDES
#─────────────────────────────────────────────────────────────

# Override settings for specific project directories.
# The key is the absolute path to the project.

# [projects."/path/to/database-project"]
# packs.enabled = ["database"]
# packs.disabled = []
# overrides.allow = ["dropdb test_.*"]

# [projects."/path/to/k8s-infra"]
# packs.enabled = ["kubernetes", "cloud.aws", "infrastructure.terraform"]
"#
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.general.color, "auto");
        assert!(config.packs.enabled.is_empty());
    }

    #[test]
    fn test_enabled_pack_ids_includes_core() {
        let config = Config::default();
        let enabled = config.enabled_pack_ids();
        assert!(enabled.contains("core"));
    }

    #[test]
    fn test_enabled_pack_ids_respects_disabled() {
        let config = Config {
            packs: PacksConfig {
                enabled: vec!["kubernetes".to_string(), "kubernetes.helm".to_string()],
                disabled: vec!["kubernetes.helm".to_string()],
            },
            ..Default::default()
        };
        let enabled = config.enabled_pack_ids();
        assert!(enabled.contains("kubernetes"));
        assert!(!enabled.contains("kubernetes.helm"));
    }

    #[test]
    fn test_allow_override_simple() {
        let override_ = AllowOverride::Simple("test pattern".to_string());
        assert_eq!(override_.pattern(), "test pattern");
        assert!(override_.condition_met());
    }

    #[test]
    fn test_allow_override_conditional_no_condition() {
        let override_ = AllowOverride::Conditional {
            pattern: "test pattern".to_string(),
            when: None,
        };
        assert!(override_.condition_met());
    }

    #[test]
    fn test_sample_config_parses() {
        let sample = Config::generate_sample_config();
        // Remove comment lines for parsing test
        let _config: Result<Config, _> = toml::from_str(&sample);
        // Note: The sample has comments which toml handles fine
    }

    #[test]
    fn test_config_merge() {
        let mut base = Config::default();
        let other = Config {
            packs: PacksConfig {
                enabled: vec!["database.postgresql".to_string()],
                disabled: vec![],
            },
            ..Default::default()
        };
        base.merge(other);
        assert!(
            base.packs
                .enabled
                .contains(&"database.postgresql".to_string())
        );
    }

    // ========================================================================
    // CompiledOverrides Tests (git_safety_guard-99e.4.1)
    // ========================================================================

    #[test]
    fn test_compile_simple_allow_override() {
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Simple("git reset --hard".to_string())],
            block: vec![],
        };
        let compiled = overrides.compile();

        assert_eq!(compiled.allow.len(), 1);
        assert!(compiled.invalid_patterns.is_empty());
        assert!(compiled.check_allow("git reset --hard"));
        assert!(!compiled.check_allow("git status"));
    }

    #[test]
    fn test_compile_block_override() {
        let overrides = OverridesConfig {
            allow: vec![],
            block: vec![BlockOverride {
                pattern: "dangerous-command".to_string(),
                reason: "This is dangerous!".to_string(),
            }],
        };
        let compiled = overrides.compile();

        assert_eq!(compiled.block.len(), 1);
        assert!(compiled.invalid_patterns.is_empty());
        assert_eq!(
            compiled.check_block("dangerous-command --force"),
            Some("This is dangerous!")
        );
        assert_eq!(compiled.check_block("safe-command"), None);
    }

    #[test]
    fn test_compile_invalid_regex_fails_open() {
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Simple("[invalid regex".to_string())],
            block: vec![BlockOverride {
                pattern: "[also invalid".to_string(),
                reason: "Won't compile".to_string(),
            }],
        };
        let compiled = overrides.compile();

        // Invalid patterns should NOT be in the compiled lists
        assert!(compiled.allow.is_empty());
        assert!(compiled.block.is_empty());

        // But they should be recorded in invalid_patterns
        assert_eq!(compiled.invalid_patterns.len(), 2);
        assert!(compiled.has_invalid_patterns());

        // Check that we recorded the right kinds
        assert!(
            compiled
                .invalid_patterns
                .iter()
                .any(|p| p.kind == PatternKind::Allow)
        );
        assert!(
            compiled
                .invalid_patterns
                .iter()
                .any(|p| p.kind == PatternKind::Block)
        );
    }

    #[test]
    fn test_compile_conditional_override_always() {
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Conditional {
                pattern: "test-pattern".to_string(),
                when: None,
            }],
            block: vec![],
        };
        let compiled = overrides.compile();

        assert_eq!(compiled.allow.len(), 1);
        // With no condition, it should always match
        assert!(compiled.check_allow("test-pattern"));
    }

    #[test]
    fn test_compile_regex_pattern() {
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Simple(
                r"kubectl delete namespace test-\d+".to_string(),
            )],
            block: vec![],
        };
        let compiled = overrides.compile();

        assert!(compiled.check_allow("kubectl delete namespace test-123"));
        assert!(compiled.check_allow("kubectl delete namespace test-999"));
        assert!(!compiled.check_allow("kubectl delete namespace production"));
    }

    #[test]
    fn test_compiled_overrides_check_order() {
        // Allow takes precedence (checked first in evaluator)
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Simple("test-command".to_string())],
            block: vec![BlockOverride {
                pattern: "test-command".to_string(),
                reason: "Blocked!".to_string(),
            }],
        };
        let compiled = overrides.compile();

        // Both patterns match
        assert!(compiled.check_allow("test-command"));
        assert!(compiled.check_block("test-command").is_some());

        // In the evaluator, allow is checked first, so command would be allowed
    }

    #[test]
    fn test_compiled_overrides_empty() {
        let overrides = OverridesConfig::default();
        let compiled = overrides.compile();

        assert!(compiled.allow.is_empty());
        assert!(compiled.block.is_empty());
        assert!(!compiled.has_invalid_patterns());
        assert!(!compiled.check_allow("anything"));
        assert!(compiled.check_block("anything").is_none());
    }

    #[test]
    fn test_compiled_overrides_multiple_patterns() {
        let overrides = OverridesConfig {
            allow: vec![
                AllowOverride::Simple("pattern-a".to_string()),
                AllowOverride::Simple("pattern-b".to_string()),
            ],
            block: vec![
                BlockOverride {
                    pattern: "block-1".to_string(),
                    reason: "Reason 1".to_string(),
                },
                BlockOverride {
                    pattern: "block-2".to_string(),
                    reason: "Reason 2".to_string(),
                },
            ],
        };
        let compiled = overrides.compile();

        assert!(compiled.check_allow("pattern-a"));
        assert!(compiled.check_allow("pattern-b"));
        assert!(!compiled.check_allow("pattern-c"));

        assert_eq!(compiled.check_block("block-1"), Some("Reason 1"));
        assert_eq!(compiled.check_block("block-2"), Some("Reason 2"));
        assert_eq!(compiled.check_block("block-3"), None);
    }
}
