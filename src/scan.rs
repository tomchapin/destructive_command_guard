//! Repository scanning (`dcg scan`) for destructive commands.
//!
//! This module is intentionally **extractor-based** (not naive substring grep).
//! The core idea is to extract only *executable contexts* from files, then
//! evaluate extracted commands using the shared evaluator pipeline.
//!
//! # Extraction contract
//!
//! Each extractor returns `ExtractedCommand` entries:
//!
//! - `file`, `line`, optional `col`
//! - `extractor_id` identifying the execution context (e.g. `shell.script`)
//! - `command` (the extracted executable command text)
//! - optional `metadata` (structured context for debugging / future UX)
//!
//! Extractors MUST be conservative: if unsure whether something is executed,
//! prefer returning no extraction rather than producing false positives.
//!
//! # Output schema (v1)
//!
//! `dcg scan --format json` emits a `ScanReport` containing:
//! - stable ordering of findings (deterministic output for CI / PR comments)
//! - `decision` in {allow,warn,deny}
//! - `severity` in {info,warning,error}
//! - stable `rule_id` (`pack_id:pattern_name`) when available
//!
//! Note: the shared evaluator currently only blocks deny-by-default pack rules.
//! Scan output uses this evaluator behavior for parity.

use crate::config::{Config, HeredocSettings};
use crate::evaluator::{
    EvaluationDecision, MatchSource, PatternMatch, evaluate_command_with_pack_order,
};
use crate::packs::{DecisionMode, REGISTRY, Severity};
use crate::suggestions::{SuggestionKind, get_suggestion_by_kind};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

pub const SCAN_SCHEMA_VERSION: u32 = 1;

/// Scan output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ScanFormat {
    Pretty,
    Json,
}

/// Controls scan failure behavior (CI integration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ScanFailOn {
    None,
    Warning,
    Error,
}

impl ScanFailOn {
    #[must_use]
    pub const fn blocks(&self, severity: ScanSeverity) -> bool {
        match self {
            Self::None => false,
            Self::Warning => matches!(severity, ScanSeverity::Warning | ScanSeverity::Error),
            Self::Error => matches!(severity, ScanSeverity::Error),
        }
    }
}

/// Redaction mode for scan output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ScanRedactMode {
    /// No redaction.
    #[default]
    None,
    /// Redact quoted strings.
    Quoted,
    /// Aggressive redaction (quoted strings + likely sensitive spans).
    Aggressive,
}

/// Scan decision for an extracted command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanDecision {
    Allow,
    Warn,
    Deny,
}

/// Scan severity (used for `--fail-on` policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanSeverity {
    Info,
    Warning,
    Error,
}

impl ScanSeverity {
    #[must_use]
    pub const fn rank(&self) -> u8 {
        match self {
            Self::Error => 3,
            Self::Warning => 2,
            Self::Info => 1,
        }
    }
}

/// Extracted executable command from a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedCommand {
    pub file: String,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub col: Option<usize>,
    pub extractor_id: String,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// A scan finding produced by evaluating an extracted command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub file: String,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub col: Option<usize>,
    pub extractor_id: String,
    pub extracted_command: String,
    pub decision: ScanDecision,
    pub severity: ScanSeverity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

/// Counts of findings by decision.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanDecisionCounts {
    pub allow: usize,
    pub warn: usize,
    pub deny: usize,
}

/// Counts of findings by severity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanSeverityCounts {
    pub info: usize,
    pub warning: usize,
    pub error: usize,
}

/// Summary statistics for a scan run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub commands_extracted: usize,
    pub findings_total: usize,
    pub decisions: ScanDecisionCounts,
    pub severities: ScanSeverityCounts,
    pub max_findings_reached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
}

/// Complete scan output (stable JSON schema).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub summary: ScanSummary,
    pub findings: Vec<ScanFinding>,
}

/// In-memory scan configuration (CLI + defaults).
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub format: ScanFormat,
    pub fail_on: ScanFailOn,
    pub max_file_size_bytes: u64,
    pub max_findings: usize,
    pub redact: ScanRedactMode,
    /// Truncate extracted commands in output (chars). 0 disables truncation.
    pub truncate: usize,
}

/// Precomputed evaluator context for scanning.
#[derive(Debug)]
pub struct ScanEvalContext {
    pub enabled_keywords: Vec<&'static str>,
    pub ordered_packs: Vec<String>,
    pub compiled_overrides: crate::config::CompiledOverrides,
    pub allowlists: crate::allowlist::LayeredAllowlist,
    pub heredoc_settings: HeredocSettings,
}

impl ScanEvalContext {
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        let enabled_packs: HashSet<String> = config.enabled_pack_ids();
        let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
        let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
        let compiled_overrides = config.overrides.compile();
        let allowlists = crate::load_default_allowlists();
        let heredoc_settings = config.heredoc_settings();

        Self {
            enabled_keywords,
            ordered_packs,
            compiled_overrides,
            allowlists,
            heredoc_settings,
        }
    }
}

#[must_use]
pub fn should_fail(report: &ScanReport, fail_on: ScanFailOn) -> bool {
    report.findings.iter().any(|f| fail_on.blocks(f.severity))
}

pub fn sort_findings(findings: &mut [ScanFinding]) {
    findings.sort_by(|a, b| {
        let key_a = (
            a.file.as_str(),
            a.line,
            a.col.unwrap_or(0),
            a.rule_id.as_deref().unwrap_or(a.extractor_id.as_str()),
            a.extractor_id.as_str(),
            a.severity.rank(),
            a.extracted_command.as_str(),
        );
        let key_b = (
            b.file.as_str(),
            b.line,
            b.col.unwrap_or(0),
            b.rule_id.as_deref().unwrap_or(b.extractor_id.as_str()),
            b.extractor_id.as_str(),
            b.severity.rank(),
            b.extracted_command.as_str(),
        );
        key_a.cmp(&key_b)
    });
}

#[must_use]
pub fn evaluate_extracted_command(
    extracted: &ExtractedCommand,
    options: &ScanOptions,
    config: &Config,
    ctx: &ScanEvalContext,
) -> Option<ScanFinding> {
    let result = evaluate_command_with_pack_order(
        &extracted.command,
        &ctx.enabled_keywords,
        &ctx.ordered_packs,
        &ctx.compiled_overrides,
        &ctx.allowlists,
        &ctx.heredoc_settings,
    );

    if result.decision == EvaluationDecision::Allow {
        return None;
    }

    let Some(pattern) = result.pattern_info else {
        return Some(ScanFinding {
            file: extracted.file.clone(),
            line: extracted.line,
            col: extracted.col,
            extractor_id: extracted.extractor_id.clone(),
            extracted_command: extracted.command.clone(),
            decision: ScanDecision::Deny,
            severity: ScanSeverity::Error,
            rule_id: None,
            reason: Some("Blocked (missing match metadata)".to_string()),
            suggestion: None,
        });
    };

    let (rule_id, severity, decision_mode) = resolve_severity_and_rule_id(config, &pattern);

    let scan_decision = match decision_mode {
        Some(DecisionMode::Deny) | None => ScanDecision::Deny,
        Some(DecisionMode::Warn) => ScanDecision::Warn,
        Some(DecisionMode::Log) => ScanDecision::Allow,
    };

    let scan_severity = match severity {
        Some(Severity::Medium) => ScanSeverity::Warning,
        Some(Severity::Low) => ScanSeverity::Info,
        Some(Severity::Critical | Severity::High) | None => ScanSeverity::Error,
    };

    let suggestion = rule_id
        .as_deref()
        .and_then(|id| get_suggestion_by_kind(id, SuggestionKind::SaferAlternative))
        .map(|s| s.text.clone());

    let extracted_command = redact_and_truncate(&extracted.command, options);

    Some(ScanFinding {
        file: extracted.file.clone(),
        line: extracted.line,
        col: extracted.col,
        extractor_id: extracted.extractor_id.clone(),
        extracted_command,
        decision: scan_decision,
        severity: scan_severity,
        rule_id,
        reason: Some(pattern.reason),
        suggestion,
    })
}

fn resolve_severity_and_rule_id(
    config: &Config,
    pattern: &PatternMatch,
) -> (Option<String>, Option<Severity>, Option<DecisionMode>) {
    let Some(pack_id) = pattern.pack_id.as_deref() else {
        return (None, None, None);
    };

    let Some(pattern_name) = pattern.pattern_name.as_deref() else {
        return (None, None, None);
    };

    let rule_id = Some(format!("{pack_id}:{pattern_name}"));

    let severity = pattern.severity;

    // Never downgrade explicit blocks; packs/AST matches are policy-controlled.
    let mode = match pattern.source {
        MatchSource::Pack | MatchSource::HeredocAst => {
            config
                .policy()
                .resolve_mode(Some(pack_id), Some(pattern_name), severity)
        }
        MatchSource::ConfigOverride | MatchSource::LegacyPattern => DecisionMode::Deny,
    };

    (rule_id, severity, Some(mode))
}

fn redact_and_truncate(command: &str, options: &ScanOptions) -> String {
    let redacted = match options.redact {
        ScanRedactMode::None => command.to_string(),
        ScanRedactMode::Quoted => redact_quoted_strings(command),
        ScanRedactMode::Aggressive => redact_aggressively(command),
    };

    truncate_utf8(&redacted, options.truncate)
}

fn truncate_utf8(s: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return s.to_string();
    }

    if max_chars == 1 {
        return "…".to_string();
    }

    let cut = max_chars - 1;
    for (count, (idx, _)) in s.char_indices().enumerate() {
        if count == cut {
            return format!("{}…", &s[..idx]);
        }
    }

    s.to_string()
}

fn redact_quoted_strings(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();

    while let Some(c) = it.next() {
        match c {
            '\'' => {
                out.push('\'');
                out.push('…');
                for next in it.by_ref() {
                    if next == '\'' {
                        out.push('\'');
                        break;
                    }
                }
            }
            '"' => {
                out.push('"');
                out.push('…');
                let mut escaped = false;
                for next in it.by_ref() {
                    if escaped {
                        escaped = false;
                        continue;
                    }
                    if next == '\\' {
                        escaped = true;
                        continue;
                    }
                    if next == '"' {
                        out.push('"');
                        break;
                    }
                }
            }
            _ => out.push(c),
        }
    }

    out
}

fn redact_aggressively(s: &str) -> String {
    // First pass: redact quoted strings (most likely secret-bearing spans).
    let s = redact_quoted_strings(s);

    // Second pass: redact KEY=VALUE tokens when key looks secret-y.
    // This keeps output debuggable while avoiding accidental leakage.
    let mut out = String::with_capacity(s.len());
    let mut token = String::new();

    for c in s.chars() {
        if c.is_whitespace() {
            if !token.is_empty() {
                out.push_str(&redact_token(&token));
                token.clear();
            }
            out.push(c);
        } else {
            token.push(c);
        }
    }

    if !token.is_empty() {
        out.push_str(&redact_token(&token));
    }

    out
}

fn redact_token(token: &str) -> String {
    // Redact long hex-ish blobs (common for hashes/keys).
    if token.len() >= 32 && token.chars().all(|c| c.is_ascii_hexdigit()) {
        return "…".to_string();
    }

    if let Some(eq) = token.find('=') {
        let lower = token[..eq].to_ascii_lowercase();
        let (k, _v) = token.split_at(eq + 1);
        if lower.contains("token")
            || lower.contains("secret")
            || lower.contains("password")
            || lower.contains("passwd")
            || lower.contains("api_key")
            || lower.contains("apikey")
            || lower.contains("bearer")
        {
            return format!("{k}…");
        }
    }

    token.to_string()
}

/// Scan file paths (directories are expanded recursively).
///
/// This is a small, conservative implementation intended to support the `scan`
/// epic without pulling in heavy parsing dependencies. Extraction is delegated
/// to extractor modules (implemented in follow-up tasks).
///
/// Currently this function does **not** implement extractors; it is a framework
/// for deterministic output and evaluator integration.
#[allow(clippy::missing_errors_doc)]
#[allow(clippy::missing_const_for_fn)] // Can't be const: returns Result with Vec::new()
pub fn scan_paths(
    paths: &[PathBuf],
    options: &ScanOptions,
    _config: &Config,
    _ctx: &ScanEvalContext,
) -> Result<ScanReport, String> {
    let started = std::time::Instant::now();

    // NOTE: Extractors are implemented in follow-up beads. This function currently only
    // computes deterministic file/summary statistics and returns an empty finding list.
    //
    // This ensures `dcg scan` output is still well-formed and stable while extraction
    // work proceeds, and it gives CI integrations a schema to build around.

    let mut files: Vec<PathBuf> = Vec::new();
    for path in paths {
        collect_files_recursively(path, &mut files);
    }

    files.sort();
    files.dedup();

    let mut files_scanned = 0usize;
    let mut files_skipped = 0usize;

    for file in &files {
        let Ok(meta) = std::fs::metadata(file) else {
            files_skipped += 1;
            continue;
        };

        if !meta.is_file() {
            files_skipped += 1;
            continue;
        }

        if meta.len() > options.max_file_size_bytes {
            files_skipped += 1;
            continue;
        }

        files_scanned += 1;
    }

    let findings: Vec<ScanFinding> = Vec::new();

    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).ok();
    Ok(build_report(
        findings,
        files_scanned,
        files_skipped,
        0,
        false,
        elapsed_ms,
    ))
}

fn collect_files_recursively(path: &PathBuf, out: &mut Vec<PathBuf>) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };

    if meta.is_file() {
        out.push(path.clone());
        return;
    }

    if !meta.is_dir() {
        return;
    }

    let Ok(read_dir) = std::fs::read_dir(path) else {
        return;
    };

    // Deterministic traversal: sort entries by path.
    let mut entries: Vec<PathBuf> = read_dir.filter_map(|e| e.ok().map(|e| e.path())).collect();
    entries.sort();

    for entry in entries {
        collect_files_recursively(&entry, out);
    }
}

#[must_use]
pub fn build_report(
    mut findings: Vec<ScanFinding>,
    files_scanned: usize,
    files_skipped: usize,
    commands_extracted: usize,
    max_findings_reached: bool,
    elapsed_ms: Option<u64>,
) -> ScanReport {
    sort_findings(&mut findings);

    let mut decisions = ScanDecisionCounts::default();
    let mut severities = ScanSeverityCounts::default();

    for f in &findings {
        match f.decision {
            ScanDecision::Allow => decisions.allow += 1,
            ScanDecision::Warn => decisions.warn += 1,
            ScanDecision::Deny => decisions.deny += 1,
        }

        match f.severity {
            ScanSeverity::Info => severities.info += 1,
            ScanSeverity::Warning => severities.warning += 1,
            ScanSeverity::Error => severities.error += 1,
        }
    }

    ScanReport {
        schema_version: SCAN_SCHEMA_VERSION,
        summary: ScanSummary {
            files_scanned,
            files_skipped,
            commands_extracted,
            findings_total: findings.len(),
            decisions,
            severities,
            max_findings_reached,
            elapsed_ms,
        },
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> Config {
        Config::default()
    }

    #[test]
    fn fail_on_policy_blocks_as_expected() {
        let report = build_report(
            vec![
                ScanFinding {
                    file: "a".to_string(),
                    line: 1,
                    col: None,
                    extractor_id: "x".to_string(),
                    extracted_command: "rm -rf /".to_string(),
                    decision: ScanDecision::Deny,
                    severity: ScanSeverity::Error,
                    rule_id: Some("core.filesystem:rm-rf-general".to_string()),
                    reason: Some("blocked".to_string()),
                    suggestion: None,
                },
                ScanFinding {
                    file: "b".to_string(),
                    line: 1,
                    col: None,
                    extractor_id: "x".to_string(),
                    extracted_command: "echo hi".to_string(),
                    decision: ScanDecision::Warn,
                    severity: ScanSeverity::Warning,
                    rule_id: None,
                    reason: Some("warn".to_string()),
                    suggestion: None,
                },
            ],
            2,
            0,
            2,
            false,
            None,
        );

        assert!(should_fail(&report, ScanFailOn::Error));
        assert!(should_fail(&report, ScanFailOn::Warning));
        assert!(!should_fail(&report, ScanFailOn::None));
    }

    #[test]
    fn finding_order_is_deterministic() {
        let mut findings = vec![
            ScanFinding {
                file: "b".to_string(),
                line: 2,
                col: None,
                extractor_id: "x".to_string(),
                extracted_command: "cmd".to_string(),
                decision: ScanDecision::Warn,
                severity: ScanSeverity::Warning,
                rule_id: Some("pack:rule".to_string()),
                reason: None,
                suggestion: None,
            },
            ScanFinding {
                file: "a".to_string(),
                line: 1,
                col: None,
                extractor_id: "x".to_string(),
                extracted_command: "cmd".to_string(),
                decision: ScanDecision::Deny,
                severity: ScanSeverity::Error,
                rule_id: Some("pack:rule".to_string()),
                reason: None,
                suggestion: None,
            },
        ];

        sort_findings(&mut findings);
        assert_eq!(findings[0].file, "a");
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn evaluator_integration_maps_pack_rule_to_rule_id() {
        let config = default_config();
        let ctx = ScanEvalContext::from_config(&config);
        let options = ScanOptions {
            format: ScanFormat::Pretty,
            fail_on: ScanFailOn::Error,
            max_file_size_bytes: 1024 * 1024,
            max_findings: 100,
            redact: ScanRedactMode::None,
            truncate: 0,
        };
        let extracted = ExtractedCommand {
            file: "test".to_string(),
            line: 1,
            col: None,
            extractor_id: "shell.script".to_string(),
            command: "git reset --hard".to_string(),
            metadata: None,
        };

        let finding = evaluate_extracted_command(&extracted, &options, &config, &ctx)
            .expect("git reset --hard should be blocked");
        assert_eq!(finding.decision, ScanDecision::Deny);
        assert_eq!(finding.severity, ScanSeverity::Error);
        assert_eq!(finding.rule_id.as_deref(), Some("core.git:reset-hard"));
        assert!(finding.reason.is_some());
    }
}
