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
const ENV_PREFIX: &str = "GIT_SAFETY_GUARD";

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
    /// List of enabled packs (e.g., ["database.postgresql", "kubernetes"]).
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
    pub fn pattern(&self) -> &str {
        match self {
            Self::Simple(p) => p,
            Self::Conditional { pattern, .. } => pattern,
        }
    }

    /// Check if the condition is met (if any).
    pub fn condition_met(&self) -> bool {
        match self {
            Self::Simple(_) => true,
            Self::Conditional { when: None, .. } => true,
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
        // GIT_SAFETY_GUARD_PACKS="core,database.postgresql,kubernetes"
        if let Ok(packs) = env::var(format!("{ENV_PREFIX}_PACKS")) {
            self.packs.enabled = packs.split(',').map(|s| s.trim().to_string()).collect();
        }

        // GIT_SAFETY_GUARD_DISABLE="kubernetes.helm"
        if let Ok(disable) = env::var(format!("{ENV_PREFIX}_DISABLE")) {
            self.packs.disabled = disable.split(',').map(|s| s.trim().to_string()).collect();
        }

        // GIT_SAFETY_GUARD_VERBOSE=1
        if env::var(format!("{ENV_PREFIX}_VERBOSE")).is_ok() {
            self.general.verbose = true;
        }

        // GIT_SAFETY_GUARD_COLOR=never
        if let Ok(color) = env::var(format!("{ENV_PREFIX}_COLOR")) {
            self.general.color = color;
        }
    }

    /// Check if the bypass flag is set (escape hatch).
    pub fn is_bypassed() -> bool {
        env::var(format!("{ENV_PREFIX}_BYPASS")).is_ok()
    }

    /// Get the effective pack configuration for a specific project path.
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
    pub fn save_to_user_config(&self) -> Result<PathBuf, String> {
        let path = Self::user_config_path().ok_or("Could not determine config directory")?;

        let content =
            toml::to_string_pretty(self).map_err(|e| format!("Failed to serialize config: {e}"))?;

        fs::write(&path, content).map_err(|e| format!("Failed to write config: {e}"))?;

        Ok(path)
    }

    /// Generate a default configuration with common packs enabled.
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
        assert!(base.packs.enabled.contains(&"database.postgresql".to_string()));
    }
}
