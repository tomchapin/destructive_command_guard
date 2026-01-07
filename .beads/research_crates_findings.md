# Research Findings: tree-sitter and ast-grep Rust Crates

## Executive Summary

Both tree-sitter and ast-grep are available as Rust crates with excellent ecosystem support. The recommended approach is to use **ast-grep-core** + **ast-grep-language** for the most complete solution, with tree-sitter grammars as an alternative for a smaller footprint.

## tree-sitter Ecosystem

### Core Crate: tree-sitter

- **Version**: 0.26.3 (latest as of Jan 2026)
- **License**: MIT
- **Downloads**: 11M+ all-time (very mature)
- **Source**: https://crates.io/crates/tree-sitter

```toml
tree-sitter = "0.26.3"
```

### Language Grammars Available

| Language | Crate | Version | Status |
|----------|-------|---------|--------|
| Bash | tree-sitter-bash | ^0.23.0 | ✅ Available |
| Python | tree-sitter-python | ^0.23.0 | ✅ Available |
| JavaScript | tree-sitter-javascript | ^0.23.0 | ✅ Available |
| TypeScript | tree-sitter-typescript | ^0.23.0 | ✅ Available |
| Ruby | tree-sitter-ruby | Available | ✅ Available |
| Perl | tree-sitter-perl | Unknown | ⚠️ May not exist as crate |

### tree-sitter Features

- Incremental parsing (fast re-parsing of edited code)
- Error recovery (useful for incomplete heredoc code)
- Query language (S-expression based pattern matching)
- Syntax highlighting queries available per grammar

## ast-grep Ecosystem

### Core Crate: ast-grep-core

- **Version**: 0.40.4
- **License**: MIT
- **Depends on**: tree-sitter ^0.26.3
- **Source**: https://crates.io/crates/ast-grep-core
- **Docs**: https://docs.rs/ast-grep-core/latest/ast_grep_core/

```toml
ast-grep-core = "0.40"
```

Key structs:
- `Node` - Represents tree-sitter nodes
- `Pattern` - AST-based pattern matching
- `Matcher` trait - Defines matching behavior
- `AstGrep` type alias - Main entry point

### Language Support: ast-grep-language

- **Version**: 0.37.0
- **Source**: https://crates.io/crates/ast-grep-language
- **Feature**: All languages are OPTIONAL features

```toml
[dependencies]
ast-grep-language = { version = "0.37", features = ["bash", "python", "javascript"] }
```

Supported languages (via optional features):
- Bash ✅
- Python ✅
- JavaScript ✅
- TypeScript ✅
- Ruby ✅
- C, C++, C#, CSS, Elixir, Go, Haskell, HTML, Java, JSON, Kotlin, Lua, PHP

### ast-grep Pattern Syntax

Patterns look like ordinary code with `$METAVAR` wildcards:
```
os.system($CMD)           # Matches any os.system() call
subprocess.call($$$ARGS)  # Matches subprocess.call with any args
```

## Comparison: tree-sitter Queries vs ast-grep Patterns

### tree-sitter Queries (S-expressions)

```scheme
(call_expression
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#eq? @obj "os")
  (#eq? @method "system"))
```

**Pros**: Built into tree-sitter, well-documented, no extra deps
**Cons**: Verbose, steeper learning curve

### ast-grep Patterns

```
os.system($CMD)
```

**Pros**: Intuitive (looks like code), powerful metavariables
**Cons**: Extra dependency (ast-grep-core)

## Recommended Approach for dcg

### Option A: Minimal (tree-sitter only)

```toml
[dependencies]
tree-sitter = "0.26"
tree-sitter-bash = "0.23"
tree-sitter-python = "0.23"
tree-sitter-javascript = "0.23"
# ... etc
```

Use tree-sitter queries for pattern matching. More verbose but fewer dependencies.

### Option B: Full Featured (ast-grep)

```toml
[dependencies]
ast-grep-core = "0.40"
ast-grep-language = { version = "0.37", features = ["bash", "python", "javascript", "typescript", "ruby"] }
```

Use ast-grep patterns for matching. More expressive, less code, but larger dependency.

### Recommendation: Option B (ast-grep)

Reasons:
1. **Pattern expressiveness**: ast-grep patterns are much easier to write and maintain
2. **Battle-tested**: ast-grep is widely used for linting and code search
3. **Language support**: ast-grep-language handles grammar loading
4. **Documentation**: Despite low docs coverage, patterns are intuitive
5. **Maintenance**: Upstream maintains language support

Tradeoffs:
- Slightly larger binary (~2-3MB more)
- More dependencies in Cargo.lock
- Less control over grammar versions

### Perl Language Note

Perl may not have reliable tree-sitter/ast-grep support. Options:
1. Defer Perl support (lower priority)
2. Use regex fallback for Perl heredocs
3. Research tree-sitter-perl grammar separately

## Binary Size Estimates

| Configuration | Estimated Size Addition |
|---------------|------------------------|
| tree-sitter core only | ~500KB |
| Per language grammar | ~500KB-2MB each |
| 5 languages (bash, python, js, ts, ruby) | ~5-8MB total |
| ast-grep-core | ~400KB |
| ast-grep-language (5 langs) | ~6-10MB total |

Current dcg release binary: ~1.2MB
Estimated with heredoc support: ~8-12MB

## Performance Expectations

Based on tree-sitter benchmarks and ast-grep usage:

| Operation | Expected Latency |
|-----------|-----------------|
| Grammar load (once at startup) | 10-50ms |
| Parse small heredoc (<100 lines) | <1ms |
| Parse medium heredoc (100-500 lines) | 1-5ms |
| Pattern match per pattern | <0.1ms |
| Full heredoc check (parse + patterns) | <5ms |

These are well within our 50ms budget for heredoc analysis.

## Sources

- [tree-sitter on crates.io](https://crates.io/crates/tree-sitter)
- [ast-grep-core on crates.io](https://crates.io/crates/ast-grep-core)
- [ast-grep-core documentation](https://docs.rs/ast-grep-core/latest/ast_grep_core/)
- [ast-grep GitHub repository](https://github.com/ast-grep/ast-grep)
- [tree-sitter-bash on crates.io](https://crates.io/crates/tree-sitter-bash)
- [tree-sitter-python on lib.rs](https://lib.rs/crates/tree-sitter-python)
- [tree-sitter-ruby on crates.io](https://crates.io/crates/tree-sitter-ruby)
