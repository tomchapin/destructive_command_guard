//! Destructive Command Guard (dcg) library.
//!
//! This library provides the core functionality for blocking destructive commands
//! in AI coding agent workflows. It supports modular "packs" of patterns for
//! different use cases (databases, containers, Kubernetes, cloud providers, etc.).
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        Configuration                             │
//! │  (env vars → project config → user config → system → defaults)  │
//! └─────────────────────────────────────────────────────────────────┘
//!                                  │
//!                                  ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         Pack Registry                            │
//! │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
//! │  │   Core   │ │ Database │ │  K8s     │ │  Cloud   │  ...      │
//! │  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
//! └─────────────────────────────────────────────────────────────────┘
//!                                  │
//!                                  ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      Pattern Matching                            │
//! │  Quick Reject (memchr) → Safe Patterns → Destructive Patterns   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

pub mod cli;
pub mod config;
pub mod hook;
pub mod packs;

// Re-export commonly used types
pub use config::Config;
pub use hook::{HookInput, HookOutput, HookResult};
pub use packs::{Pack, PackId, PackRegistry};
