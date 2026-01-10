# Pack Implementation Completion Checklist

Use this checklist before marking any pack as complete. It is intentionally
strict: the goal is correctness, low false positives, and consistent quality.

## Pre-Merge Checklist

### Code Quality
- [ ] Pack follows existing code patterns (reference `src/packs/database/postgresql.rs`)
- [ ] Regex complexity is appropriate (no catastrophic backtracking)
- [ ] Keywords are minimal and specific
- [ ] No duplicate patterns with other packs
- [ ] Code passes `cargo fmt`, `cargo clippy`, `cargo check`

### Destructive Pattern Coverage
- [ ] All known destructive commands are covered
- [ ] Each pattern has a clear, specific reason string
- [ ] Patterns do not over-match (too broad)
- [ ] Patterns do not under-match (miss variations)

### Safe Pattern Coverage
- [ ] Common safe commands are explicitly allowed
- [ ] Safe patterns take precedence correctly
- [ ] Read-only operations are not blocked

### Unit Tests
- [ ] Tests live in `src/packs/<category>/<pack>.rs` under `#[cfg(test)]`
- [ ] Each destructive pattern has at least one test
- [ ] Each safe pattern has at least one test
- [ ] Edge cases tested (quotes, special chars, empty input)
- [ ] Pack code coverage >= 90%

### E2E Tests
- [ ] Test file exists: `scripts/e2e_tests/<pack>.txt`
- [ ] Real-world command examples included
- [ ] Both block and allow cases tested
- [ ] E2E tests pass locally

### Documentation
- [ ] Pack added to README pack list
- [ ] Reference doc created: `docs/packs/<category>/<pack>.md`
- [ ] Configuration examples included
- [ ] Common issues documented

### Performance
- [ ] Pack evaluation < 500 microseconds (benchmark)
- [ ] No regex patterns flagged as slow
- [ ] Total pattern count reasonable (< 50)

### Review
- [ ] Code review completed
- [ ] Test review completed
- [ ] Documentation review completed

## Post-Merge Validation

- [ ] CI passes on main branch
- [ ] No performance regression in nightly benchmarks
- [ ] Monitor for user-reported issues (1 week)

## Sign-Off

Pack implementation approved by: ______________________
Date: ______________________

## Notes

- Verify pack e2e runs via shared harness with `--verbose` JSON logs and artifacts stored for diffing.
- Confirm per-pack allow/deny cases appear in log summary with pack_id/pattern_name.
- Confirm perf budget checks (git_safety_guard-qxc7) and CI integration (git_safety_guard-6ozg) ran for the pack.
