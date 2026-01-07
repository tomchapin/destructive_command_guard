//! MySQL/MariaDB patterns.

use crate::packs::{DestructivePattern, Pack, SafePattern};

pub fn create_pack() -> Pack {
    Pack {
        id: "database.mysql".to_string(),
        name: "MySQL/MariaDB",
        description: "MySQL/MariaDB guard",
        keywords: &["mysql", "DROP"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![]
}
