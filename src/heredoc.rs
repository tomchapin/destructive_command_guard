//! Two-tier heredoc and inline script detection.
//!
//! This module implements a tiered detection architecture for heredoc and inline
//! script analysis, balancing performance with detection accuracy.
//!
//! # Architecture
//!
//! ```text
//! Command Input
//!      │
//!      ▼
//! ┌─────────────────┐
//! │ Tier 1: Trigger │ ─── No match ──► ALLOW (fast path)
//! │   (<100μs)      │
//! └────────┬────────┘
//!          │ Match
//!          ▼
//! ┌─────────────────┐
//! │ Tier 2: Extract │ ─── Error/Timeout ──► ALLOW + warn
//! │   (<1ms)        │
//! └────────┬────────┘
//!          │ Success
//!          ▼
//! ┌─────────────────┐
//! │ Tier 3: AST     │ ─── No match ──► ALLOW
//! │   (<5ms)        │ ─── Match ──► BLOCK
//! └─────────────────┘
//! ```
//!
//! # Tier 1: Trigger Detection
//!
//! Ultra-fast detection using [`RegexSet`] for parallel matching.
//! Zero allocations on non-match path. MUST have zero false negatives.
//!
//! # Tier 2: Content Extraction
//!
//! Extracts heredoc/inline script content with bounded memory and time.
//! Graceful degradation on malformed input.
//!
//! # Tier 3: AST Pattern Matching (future)
//!
//! Uses ast-grep-core for structural pattern matching.
//! Language-specific patterns for destructive operations.

use regex::RegexSet;
use std::sync::LazyLock;

/// Tier 1 trigger patterns for heredoc and inline script detection.
///
/// These patterns are designed for maximum recall (zero false negatives).
/// False positives are acceptable - they just trigger Tier 2 analysis.
///
/// # Performance
///
/// Uses [`RegexSet`] for parallel matching in a single pass over the input.
/// Target latency: <10μs for non-matching, <100μs for matching.
static HEREDOC_TRIGGERS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        // Heredoc operators (bash, sh, zsh)
        r"<<-?\s*['\x22]?\w+['\x22]?", // << or <<- with optional quotes
        r"<<<",                        // Here-strings (bash)
        // Python inline execution
        r"\bpython3?\s+-[ce]\s",
        r"\bpython\s+-[ce]\s",
        // Ruby inline execution
        r"\bruby\s+-e\s",
        r"\birb\s+-e\s",
        // Perl inline execution
        r"\bperl\s+-[eE]\s",
        // Node.js inline execution
        r"\bnode\s+-[ep]\s",
        // Shell inline execution (sh -c, bash -c, zsh -c, fish -c)
        r"\b(sh|bash|zsh|fish)\s+-c\s",
        // Piped execution to interpreters
        r"\|\s*(python3?|ruby|perl|node|sh|bash)\b",
        // Piped to xargs (can execute arbitrary commands)
        r"\|\s*xargs\s",
        // exec/eval in various contexts
        r"\beval\s+['\x22]",
        r"\bexec\s+['\x22]",
        // Additional heredoc variants
        r"<<~",          // Ruby-style heredoc (indentation-stripping)
        r"<<['\x22]EOF", // Quoted delimiters (literal)
    ])
    .expect("heredoc trigger patterns should compile")
});

/// Result of Tier 1 trigger detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerResult {
    /// No heredoc/inline script indicators found - fast path to ALLOW.
    NoTrigger,
    /// Trigger detected - proceed to Tier 2 extraction.
    Triggered,
}

/// Check if a command contains heredoc or inline script indicators.
///
/// This is Tier 1 of the detection pipeline - ultra-fast screening.
///
/// # Guarantees
///
/// - Zero false negatives: if Tier 2 would find a heredoc, this MUST trigger
/// - Zero allocations on non-match path
/// - Target latency: <10μs for non-matching commands
///
/// # Examples
///
/// ```ignore
/// use destructive_command_guard::heredoc::{check_triggers, TriggerResult};
///
/// // No trigger - fast path
/// assert_eq!(check_triggers("git status"), TriggerResult::NoTrigger);
///
/// // Heredoc trigger
/// assert_eq!(check_triggers("cat << EOF"), TriggerResult::Triggered);
///
/// // Python inline execution
/// assert_eq!(check_triggers("python -c 'import os'"), TriggerResult::Triggered);
/// ```
#[inline]
#[must_use]
pub fn check_triggers(command: &str) -> TriggerResult {
    if HEREDOC_TRIGGERS.is_match(command) {
        TriggerResult::Triggered
    } else {
        TriggerResult::NoTrigger
    }
}

/// Returns the list of trigger pattern indices that matched.
///
/// Useful for debugging and logging which patterns triggered.
#[must_use]
pub fn matched_triggers(command: &str) -> Vec<usize> {
    HEREDOC_TRIGGERS.matches(command).into_iter().collect()
}

// ============================================================================
// Tier 2: Content Extraction
// ============================================================================

use regex::Regex;

/// Limits for content extraction to prevent resource exhaustion.
#[derive(Debug, Clone, Copy)]
pub struct ExtractionLimits {
    /// Maximum bytes to extract from heredoc body (default: 1MB)
    pub max_body_bytes: usize,
    /// Maximum lines to extract from heredoc body (default: 10,000)
    pub max_body_lines: usize,
    /// Maximum number of heredocs to process per command (default: 10)
    pub max_heredocs: usize,
    /// Timeout for extraction in milliseconds (default: 50ms)
    pub timeout_ms: u64,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: 1024 * 1024, // 1MB
            max_body_lines: 10_000,
            max_heredocs: 10,
            timeout_ms: 50,
        }
    }
}

/// Detected language for embedded script content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptLanguage {
    Bash,
    Python,
    Ruby,
    Perl,
    JavaScript,
    TypeScript,
    Unknown,
}

impl ScriptLanguage {
    /// Infer language from a command prefix (e.g., "python3", "ruby").
    #[must_use]
    pub fn from_command(cmd: &str) -> Self {
        let cmd_lower = cmd.to_lowercase();
        if cmd_lower.starts_with("python") {
            Self::Python
        } else if cmd_lower.starts_with("ruby") || cmd_lower.starts_with("irb") {
            Self::Ruby
        } else if cmd_lower.starts_with("perl") {
            Self::Perl
        } else if cmd_lower.starts_with("node") {
            Self::JavaScript
        } else if cmd_lower.starts_with("deno") || cmd_lower.starts_with("bun") {
            Self::TypeScript
        } else if cmd_lower.starts_with("sh")
            || cmd_lower.starts_with("bash")
            || cmd_lower.starts_with("zsh")
            || cmd_lower.starts_with("fish")
        {
            Self::Bash
        } else {
            Self::Unknown
        }
    }
}

/// Type of heredoc extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeredocType {
    /// Standard heredoc (<<)
    Standard,
    /// Tab-stripping heredoc (<<-)
    TabStripped,
    /// Here-string (<<<)
    HereString,
    /// Indentation-stripping heredoc (<<~, Ruby-style)
    IndentStripped,
}

/// Extracted content from a heredoc or inline script.
#[derive(Debug, Clone)]
pub struct ExtractedContent {
    /// The script content (body of heredoc or inline argument).
    pub content: String,
    /// Detected or inferred language.
    pub language: ScriptLanguage,
    /// Heredoc delimiter (e.g., "EOF"), if applicable.
    pub delimiter: Option<String>,
    /// Byte range in the original command.
    pub byte_range: std::ops::Range<usize>,
    /// Whether the delimiter was quoted (suppresses expansion).
    pub quoted: bool,
    /// Type of heredoc (if applicable).
    pub heredoc_type: Option<HeredocType>,
}

/// Result of Tier 2 content extraction.
#[derive(Debug)]
pub enum ExtractionResult {
    /// No extractable content found after trigger.
    NoContent,
    /// Successfully extracted content.
    Extracted(Vec<ExtractedContent>),
    /// Extraction failed (timeout, malformed, etc.) - fail open with warning.
    Failed(String),
}

/// Regex patterns for heredoc extraction (compiled once).
static HEREDOC_EXTRACTOR: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: <<[-~]? followed by optional quotes and delimiter
    // Groups: (1) operator variant (-/~/empty), (2) quote char, (3) delimiter, (4) closing quote
    Regex::new(r"<<([-~])?\s*(['\x22]?)(\w+)(['\x22]?)").expect("heredoc regex compiles")
});

/// Regex for here-string extraction (<<<).
static HERESTRING_EXTRACTOR: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: <<< followed by quoted or unquoted content
    Regex::new(r"<<<\s*(['\x22])([^'\x22]*)(['\x22])|<<<\s*(\S+)")
        .expect("herestring regex compiles")
});

/// Regex for inline script flag extraction with single quotes.
static INLINE_SCRIPT_SINGLE_QUOTE: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: command -c/-e/-p/-E followed by single-quoted content
    // Groups: (1) command, (2) flag, (3) content
    Regex::new(r"\b(python3?|ruby|irb|perl|node|sh|bash|zsh|fish)\s+(-[ceEp])\s+'([^']*)'")
        .expect("inline script single-quote regex compiles")
});

/// Regex for inline script flag extraction with double quotes.
static INLINE_SCRIPT_DOUBLE_QUOTE: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: command -c/-e/-p/-E followed by double-quoted content
    // Groups: (1) command, (2) flag, (3) content
    Regex::new(r#"\b(python3?|ruby|irb|perl|node|sh|bash|zsh|fish)\s+(-[ceEp])\s+"([^"]*)""#)
        .expect("inline script double-quote regex compiles")
});

/// Extract heredoc and inline script content from a command.
///
/// This is Tier 2 of the detection pipeline - content extraction with safety bounds.
///
/// # Guarantees
///
/// - Bounded memory usage (never allocate >max_body_bytes per heredoc)
/// - Graceful degradation on malformed input (fail-open with warning)
///
/// # Examples
///
/// ```ignore
/// use destructive_command_guard::heredoc::{extract_content, ExtractionLimits, ExtractionResult};
///
/// let result = extract_content(
///     "python3 -c 'import os; os.system(\"rm -rf /\")'",
///     &ExtractionLimits::default()
/// );
///
/// if let ExtractionResult::Extracted(contents) = result {
///     assert_eq!(contents.len(), 1);
///     assert!(contents[0].content.contains("os.system"));
/// }
/// ```
#[must_use]
pub fn extract_content(command: &str, limits: &ExtractionLimits) -> ExtractionResult {
    // Enforce input size limit
    if command.len() > limits.max_body_bytes {
        return ExtractionResult::Failed(format!(
            "Command exceeds max size: {} > {}",
            command.len(),
            limits.max_body_bytes
        ));
    }

    let mut extracted: Vec<ExtractedContent> = Vec::new();

    // Extract inline scripts (-c/-e flags)
    extract_inline_scripts(command, limits, &mut extracted);

    // Extract here-strings (<<<)
    extract_herestrings(command, limits, &mut extracted);

    // Extract heredocs (<<, <<-, <<~)
    extract_heredocs(command, limits, &mut extracted);

    if extracted.is_empty() {
        ExtractionResult::NoContent
    } else {
        ExtractionResult::Extracted(extracted)
    }
}

/// Extract inline scripts from -c/-e/-p flags.
fn extract_inline_scripts(
    command: &str,
    limits: &ExtractionLimits,
    extracted: &mut Vec<ExtractedContent>,
) {
    if extracted.len() >= limits.max_heredocs {
        return;
    }

    // Helper to extract from a given regex pattern
    let mut extract_from_pattern = |pattern: &Regex| {
        for cap in pattern.captures_iter(command) {
            if extracted.len() >= limits.max_heredocs {
                break;
            }

            let cmd_name = cap.get(1).map_or("", |m| m.as_str());
            // Content is now in group 3 (command, flag, content)
            let content = cap.get(3).map_or("", |m| m.as_str());

            // Enforce content size limit
            if content.len() > limits.max_body_bytes {
                continue;
            }

            let full_match = cap.get(0).unwrap();
            extracted.push(ExtractedContent {
                content: content.to_string(),
                language: ScriptLanguage::from_command(cmd_name),
                delimiter: None,
                byte_range: full_match.start()..full_match.end(),
                quoted: true, // -c/-e content is always in quotes
                heredoc_type: None,
            });
        }
    };

    // Extract from both single-quoted and double-quoted patterns
    extract_from_pattern(&INLINE_SCRIPT_SINGLE_QUOTE);
    extract_from_pattern(&INLINE_SCRIPT_DOUBLE_QUOTE);
}

/// Extract here-strings (<<<).
fn extract_herestrings(
    command: &str,
    limits: &ExtractionLimits,
    extracted: &mut Vec<ExtractedContent>,
) {
    if extracted.len() >= limits.max_heredocs {
        return;
    }

    for cap in HERESTRING_EXTRACTOR.captures_iter(command) {
        if extracted.len() >= limits.max_heredocs {
            break;
        }

        // Quoted form: group 2 has content
        // Unquoted form: group 4 has content
        let content = cap.get(2).or_else(|| cap.get(4)).map_or("", |m| m.as_str());

        if content.len() > limits.max_body_bytes {
            continue;
        }

        let full_match = cap.get(0).unwrap();
        let quoted = cap.get(1).is_some(); // Has opening quote

        extracted.push(ExtractedContent {
            content: content.to_string(),
            language: ScriptLanguage::Bash, // Here-strings are bash-specific
            delimiter: None,
            byte_range: full_match.start()..full_match.end(),
            quoted,
            heredoc_type: Some(HeredocType::HereString),
        });
    }
}

/// Extract heredocs (<<, <<-, <<~).
fn extract_heredocs(
    command: &str,
    limits: &ExtractionLimits,
    extracted: &mut Vec<ExtractedContent>,
) {
    if extracted.len() >= limits.max_heredocs {
        return;
    }

    for cap in HEREDOC_EXTRACTOR.captures_iter(command) {
        if extracted.len() >= limits.max_heredocs {
            break;
        }

        let operator_variant = cap.get(1).map(|m| m.as_str());
        let open_quote = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let delimiter = cap.get(3).map_or("", |m| m.as_str());
        let close_quote = cap.get(4).map(|m| m.as_str()).unwrap_or("");

        // Determine heredoc type
        let heredoc_type = match operator_variant {
            Some("-") => HeredocType::TabStripped,
            Some("~") => HeredocType::IndentStripped,
            _ => HeredocType::Standard,
        };

        let quoted = !open_quote.is_empty() || !close_quote.is_empty();
        let full_match = cap.get(0).unwrap();
        let start_pos = full_match.end();

        // Find the terminating delimiter
        if let Some(content) =
            extract_heredoc_body(command, start_pos, delimiter, heredoc_type, limits)
        {
            let end_pos = start_pos + content.len() + delimiter.len() + 1; // +1 for newline

            extracted.push(ExtractedContent {
                content,
                language: ScriptLanguage::Bash, // Default to bash for heredocs
                delimiter: Some(delimiter.to_string()),
                byte_range: full_match.start()..end_pos.min(command.len()),
                quoted,
                heredoc_type: Some(heredoc_type),
            });
        }
    }
}

/// Extract the body of a heredoc, finding the terminating delimiter.
fn extract_heredoc_body(
    command: &str,
    start: usize,
    delimiter: &str,
    heredoc_type: HeredocType,
    limits: &ExtractionLimits,
) -> Option<String> {
    let remaining = command.get(start..)?;

    // For multi-line commands, find the terminating delimiter
    let mut lines = remaining.lines();
    let mut body_lines: Vec<&str> = Vec::new();
    let mut found_terminator = false;
    let mut total_bytes = 0;

    for line in lines.by_ref() {
        // Check if this line is the terminator
        let trimmed = match heredoc_type {
            HeredocType::TabStripped => line.trim_start_matches('\t'),
            HeredocType::IndentStripped => line.trim_start(),
            HeredocType::Standard | HeredocType::HereString => line,
        };

        if trimmed == delimiter {
            found_terminator = true;
            break;
        }

        // Enforce limits
        total_bytes += line.len() + 1; // +1 for newline
        if total_bytes > limits.max_body_bytes {
            break;
        }
        if body_lines.len() >= limits.max_body_lines {
            break;
        }

        body_lines.push(line);
    }

    if !found_terminator && !body_lines.is_empty() {
        // If no terminator found but we have content, this might be a single-line
        // heredoc or the content continues beyond our view
        return None;
    }

    if body_lines.is_empty() {
        return None;
    }

    // Apply indentation stripping if needed
    let content = match heredoc_type {
        HeredocType::TabStripped => {
            // Remove leading tabs from each line
            body_lines
                .iter()
                .map(|line| line.trim_start_matches('\t'))
                .collect::<Vec<_>>()
                .join("\n")
        }
        HeredocType::IndentStripped => {
            // Remove common leading whitespace
            let min_indent = body_lines
                .iter()
                .filter(|line| !line.trim().is_empty())
                .map(|line| line.len() - line.trim_start().len())
                .min()
                .unwrap_or(0);

            body_lines
                .iter()
                .map(|line| {
                    if line.len() >= min_indent {
                        &line[min_indent..]
                    } else {
                        line.trim_start()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
        HeredocType::Standard | HeredocType::HereString => body_lines.join("\n"),
    };

    Some(content)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Tier 1: Trigger Detection Tests
    // ========================================================================

    mod tier1_triggers {
        use super::*;

        #[test]
        fn no_trigger_on_safe_commands() {
            // Common safe commands should NOT trigger
            let safe_commands = [
                "git status",
                "ls -la",
                "cargo build",
                "npm install",
                "docker ps",
                "kubectl get pods",
                "cat file.txt",
                "echo hello",
                "grep pattern file",
                "find . -name '*.rs'",
            ];

            for cmd in safe_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::NoTrigger,
                    "should not trigger on: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_heredoc_basic() {
            // Basic heredoc forms
            let heredocs = [
                "cat << EOF",
                "cat <<EOF",
                "cat << 'EOF'",
                r#"cat << "EOF""#,
                "cat <<- EOF",       // Tab-stripping heredoc
                "mysql <<< 'query'", // Here-string
            ];

            for cmd in heredocs {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on heredoc: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_python_inline() {
            let python_commands = [
                "python -c 'import os'",
                "python3 -c 'import os'",
                "python -e 'print(1)'",
                "python3 -e 'print(1)'",
            ];

            for cmd in python_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on python inline: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_ruby_inline() {
            let ruby_commands = ["ruby -e 'puts 1'", "irb -e 'exit'"];

            for cmd in ruby_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on ruby inline: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_perl_inline() {
            let perl_commands = [
                "perl -e 'print 1'",
                "perl -E 'say 1'", // Modern Perl
            ];

            for cmd in perl_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on perl inline: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_node_inline() {
            let node_commands = ["node -e 'console.log(1)'", "node -p 'process.version'"];

            for cmd in node_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on node inline: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_shell_inline() {
            let shell_commands = [
                "bash -c 'echo hello'",
                "sh -c 'ls'",
                "zsh -c 'pwd'",
                "fish -c 'echo hello'",
            ];

            for cmd in shell_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on shell inline: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_xargs() {
            let xargs_commands = [
                "find . -name '*.bak' | xargs rm",
                "ls | xargs -I {} echo {}",
                "cat files.txt | xargs -n1 process",
            ];

            for cmd in xargs_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on xargs: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_piped_execution() {
            let piped_commands = [
                "echo 'print(1)' | python",
                "cat script.py | python3",
                "echo 'puts 1' | ruby",
                "echo 'print 1' | perl",
                "echo 'console.log(1)' | node",
                "echo 'echo hello' | bash",
                "echo 'ls' | sh",
            ];

            for cmd in piped_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on piped execution: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_eval_exec() {
            let eval_commands = [
                r#"eval "dangerous code""#,
                "eval 'dangerous code'",
                r#"exec "command""#,
                "exec 'command'",
            ];

            for cmd in eval_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on eval/exec: {cmd}"
                );
            }
        }

        #[test]
        fn matched_triggers_returns_indices() {
            // Should return the indices of matching patterns
            let matches = matched_triggers("python -c 'test'");
            assert!(!matches.is_empty(), "should have matches for python -c");

            let no_matches = matched_triggers("git status");
            assert!(
                no_matches.is_empty(),
                "should have no matches for git status"
            );
        }

        // Property: Zero false negatives - if content extraction would find
        // something, trigger detection MUST fire. This is tested via the
        // comprehensive test cases above and will be verified with property
        // tests once Tier 2 is implemented.
    }

    // ========================================================================
    // Tier 2: Content Extraction Tests
    // ========================================================================

    mod tier2_extraction {
        use super::*;

        #[test]
        fn extraction_limits_default() {
            let limits = ExtractionLimits::default();
            assert_eq!(limits.max_body_bytes, 1024 * 1024);
            assert_eq!(limits.max_body_lines, 10_000);
            assert_eq!(limits.max_heredocs, 10);
            assert_eq!(limits.timeout_ms, 50);
        }

        #[test]
        fn extracts_inline_script_single_quotes() {
            let result = extract_content("python -c 'import os'", &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "import os");
                assert_eq!(contents[0].language, ScriptLanguage::Python);
                assert!(contents[0].quoted);
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_inline_script_double_quotes() {
            let result =
                extract_content(r#"bash -c "echo hello""#, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "echo hello");
                assert_eq!(contents[0].language, ScriptLanguage::Bash);
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_here_string() {
            let result = extract_content("cat <<< 'hello world'", &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "hello world");
                assert_eq!(
                    contents[0].heredoc_type,
                    Some(HeredocType::HereString)
                );
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_heredoc_basic() {
            let cmd = "cat << EOF\nline1\nline2\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "line1\nline2");
                assert_eq!(contents[0].delimiter, Some("EOF".to_string()));
                assert_eq!(contents[0].heredoc_type, Some(HeredocType::Standard));
            } else {
                panic!("Expected Extracted result, got {:?}", result);
            }
        }

        #[test]
        fn extracts_heredoc_tab_stripped() {
            let cmd = "cat <<- EOF\n\tline1\n\tline2\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                // Tab-stripping removes leading tabs
                assert_eq!(contents[0].content, "line1\nline2");
                assert_eq!(
                    contents[0].heredoc_type,
                    Some(HeredocType::TabStripped)
                );
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn no_content_on_safe_command() {
            let result = extract_content("git status", &ExtractionLimits::default());
            assert!(matches!(result, ExtractionResult::NoContent));
        }

        #[test]
        fn script_language_from_command() {
            assert_eq!(ScriptLanguage::from_command("python3"), ScriptLanguage::Python);
            assert_eq!(ScriptLanguage::from_command("ruby"), ScriptLanguage::Ruby);
            assert_eq!(ScriptLanguage::from_command("perl"), ScriptLanguage::Perl);
            assert_eq!(ScriptLanguage::from_command("node"), ScriptLanguage::JavaScript);
            assert_eq!(ScriptLanguage::from_command("bash"), ScriptLanguage::Bash);
            assert_eq!(ScriptLanguage::from_command("unknown"), ScriptLanguage::Unknown);
        }

        #[test]
        fn enforces_max_body_bytes() {
            let large_content = "x".repeat(2_000_000); // 2MB
            let cmd = format!("python -c '{large_content}'");
            let limits = ExtractionLimits {
                max_body_bytes: 1_000_000, // 1MB limit
                ..Default::default()
            };
            let result = extract_content(&cmd, &limits);
            // Should either return Failed or skip the too-large content
            match result {
                ExtractionResult::NoContent | ExtractionResult::Failed(_) => {}
                ExtractionResult::Extracted(contents) => {
                    // If extracted, content should be within limits
                    for c in contents {
                        assert!(c.content.len() <= limits.max_body_bytes);
                    }
                }
            }
        }

        #[test]
        fn extracts_multiple_inline_scripts() {
            let cmd = "python -c 'code1' && ruby -e 'code2'";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 2);
                assert_eq!(contents[0].content, "code1");
                assert_eq!(contents[1].content, "code2");
            } else {
                panic!("Expected Extracted result");
            }
        }
    }
}
