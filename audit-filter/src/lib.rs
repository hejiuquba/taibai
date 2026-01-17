//! Audit Filter - Kubernetes 风格的审计日志中间件
//! 
//! 这个库提供了一个完整的审计日志解决方案，灵感来自 Kubernetes API Server 的审计机制。
//! 
//! # 核心特性
//! 
//! - **保证记录**：利用 Rust 的 Drop trait，确保审计日志在任何情况下都会被记录
//! - **Panic 安全**：能够捕获并记录 panic 情况
//! - **长请求支持**：支持流式请求的分阶段审计
//! - **异步处理**：审计事件通过 channel 异步处理，不阻塞请求
//! - **灵活策略**：支持自定义审计策略
//! 
//! # 使用示例
//! 
//! ```rust,no_run
//! use audit_filter::*;
//! use std::sync::Arc;
//! 
//! #[tokio::main]
//! async fn main() {
//!     // 1. 创建 Sink
//!     let sink = Arc::new(ConsoleSink);
//!     
//!     // 2. 创建审计处理器
//!     let processor = AuditProcessor::new(sink);
//!     
//!     // 3. 创建策略
//!     let policy = Arc::new(AlwaysAuditPolicy);
//!     
//!     // 4. 使用中间件
//!     let req = hyper::Request::new(hyper::Body::empty());
//!     let response = with_audit(
//!         req,
//!         my_handler,
//!         processor.sender(),
//!         policy,
//!         None,
//!     ).await;
//! }
//! 
//! async fn my_handler(
//!     req: hyper::Request<hyper::Body>
//! ) -> Result<hyper::Response<hyper::Body>, Box<dyn std::error::Error + Send + Sync>> {
//!     Ok(hyper::Response::new(hyper::Body::from("Hello")))
//! }
//! ```

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
pub use middleware::{with_audit, AuditResponseBodyWrapper, to_hyper_body};
pub use policy::{AlwaysAuditPolicy, PathBasedPolicy, PolicyEvaluator, LongRunningCheck, default_long_running_check};
pub use sink::{AuditProcessor, AuditSink, ConsoleSink};
pub use types::{AuditEvent, AuditStage};
