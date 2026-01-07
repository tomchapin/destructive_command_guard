//! PostgreSQL patterns - protections against destructive psql/pg commands.
//!
//! This includes patterns for:
//! - DROP DATABASE/TABLE/SCHEMA commands
//! - TRUNCATE commands
//! - dropdb CLI command
//! - pg_dump with --clean flag

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the PostgreSQL pack.
pub fn create_pack() -> Pack {
    Pack {
        id: "database.postgresql".to_string(),
        name: "PostgreSQL",
        description: "Protects against destructive PostgreSQL operations like DROP DATABASE, \
                      TRUNCATE, and dropdb",
        keywords: &["psql", "dropdb", "DROP", "TRUNCATE", "pg_dump", "postgres"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // DROP with IF EXISTS is safer (won't error if not exists)
        safe_pattern!(
            "drop-if-exists",
            r"(?i)DROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|SEQUENCE)\s+IF\s+EXISTS"
        ),
        // TRUNCATE with RESTART IDENTITY is often intentional cleanup
        safe_pattern!(
            "truncate-restart-identity",
            r"(?i)TRUNCATE\s+.*RESTART\s+IDENTITY"
        ),
        // pg_dump without --clean is safe (backup only)
        safe_pattern!(
            "pg-dump-no-clean",
            r"pg_dump\s+(?!.*--clean)(?!.*-c\b)"
        ),
        // psql with --dry-run or explain
        safe_pattern!("psql-dry-run", r"psql\s+.*--dry-run"),
        // SELECT queries are safe
        safe_pattern!(
            "select-query",
            r"(?i)^\s*SELECT\s+"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // DROP DATABASE
        destructive_pattern!(
            "drop-database",
            r"(?i)DROP\s+DATABASE\s+(?!IF\s+EXISTS)",
            "DROP DATABASE permanently deletes the entire database. Consider using IF EXISTS or backing up first."
        ),
        // DROP TABLE without IF EXISTS
        destructive_pattern!(
            "drop-table",
            r"(?i)DROP\s+TABLE\s+(?!IF\s+EXISTS)",
            "DROP TABLE permanently deletes the table. Consider using IF EXISTS or backing up first."
        ),
        // DROP SCHEMA
        destructive_pattern!(
            "drop-schema",
            r"(?i)DROP\s+SCHEMA\s+(?!IF\s+EXISTS)",
            "DROP SCHEMA permanently deletes the schema and all its objects."
        ),
        // TRUNCATE (faster than DELETE, no rollback)
        destructive_pattern!(
            "truncate-table",
            r"(?i)TRUNCATE\s+(?:TABLE\s+)?[a-zA-Z_]",
            "TRUNCATE permanently deletes all rows without logging individual deletions."
        ),
        // DELETE without WHERE (deletes all rows)
        destructive_pattern!(
            "delete-without-where",
            r"(?i)DELETE\s+FROM\s+[a-zA-Z_][a-zA-Z0-9_]*\s*(?:;|$)",
            "DELETE without WHERE clause deletes ALL rows. Add a WHERE clause or use TRUNCATE intentionally."
        ),
        // dropdb CLI command
        destructive_pattern!(
            "dropdb-cli",
            r"dropdb\s+",
            "dropdb permanently deletes the entire database. Verify the database name carefully."
        ),
        // pg_dump with --clean (drops before creating)
        destructive_pattern!(
            "pg-dump-clean",
            r"pg_dump\s+.*(?:--clean|-c\b)",
            "pg_dump --clean drops objects before creating them. This can be destructive on restore."
        ),
    ]
}

