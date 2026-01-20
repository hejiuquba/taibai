//! Audit Filter - Kubernetes 风格的审计日志中间件

pub mod body;
pub mod context;
pub mod guard;
pub mod middleware;
pub mod policy;
pub mod sink;
pub mod types;

// 重新导出主要类型
pub use body::AuditResponseBody;
pub use context::AuditContext;
pub use guard::AuditGuard;
pub use middleware::with_audit;
pub use policy::{AlwaysAuditPolicy, PathBasedPolicy, PolicyEvaluator, LongRunningCheck, default_long_running_check};
pub use sink::{AuditProcessor, AuditSink, ConsoleSink};
pub use types::{AuditEvent, AuditStage};