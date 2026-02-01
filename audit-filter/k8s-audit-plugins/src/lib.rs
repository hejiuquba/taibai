//! Kubernetes审计日志插件
//!
//! 这个crate包含了Kubernetes审计日志的各种插件实现，包括：
//! - buffered: 缓冲插件
//! - fake: 假插件（用于测试）
//! - log: 日志后端插件
//! - truncate: 截断插件
//! - webhook: Webhook插件

pub mod buffered;
pub mod fake;
pub mod log;
pub mod truncate;
pub mod webhook;
