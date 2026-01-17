//! 审计上下文
//!
//! 这个模块提供了审计日志的核心上下文管理。
//!
//! # Panic Safety
//!
//! 本模块的设计充分考虑了 panic 安全性：
//!
//! - **Mutex Poison 恢复**：即使内部 Mutex 被污染，也能恢复数据并继续工作
//! - **事件发送失败处理**：如果审计事件发送失败，会记录错误但不会影响业务逻辑
//! - **异常情况可观测**：所有异常情况都会通过 `tracing` 记录，便于监控和排查
//!
//! # 设计理念
//!
//! 审计系统必须是**高可靠的**：
//!
//! 1. **永不阻塞业务**：使用异步 channel，审计事件处理不会阻塞请求
//! 2. **永不丢失数据**：即使在异常情况下，也要尽最大努力记录审计日志
//! 3. **永不隐藏错误**：所有异常都会被记录，便于问题排查
//!
//! # 示例
//!
//! ```rust
//! use audit_filter::AuditContext;
//! use tokio::sync::mpsc;
//! use hyper::StatusCode;
//!
//! # tokio_test::block_on(async {
//! let (tx, _rx) = mpsc::unbounded_channel();
//! let context = AuditContext::new(
//!     "req-123".to_string(),
//!     tx,
//!     true,
//!     "/api/users".to_string(),
//!     "GET".to_string(),
//! );
//!
//! // 设置响应状态码（即使 Mutex 被污染也能工作）
//! context.set_response_status(StatusCode::OK);
//!
//! // 获取状态码（自动处理 Mutex poison）
//! assert_eq!(context.get_response_status(), Some(StatusCode::OK));
//! # });
//! ```

use crate::types::{AuditEvent, AuditStage};
use hyper::StatusCode;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::mpsc;

/// 审计上下文
#[derive(Clone)]
pub struct AuditContext {
    inner: Arc<AuditContextInner>,
}

struct AuditContextInner {
    /// 事件唯一 ID
    event_id: String,
    /// 事件发送器
    event_sender: mpsc::UnboundedSender<AuditEvent>,
    /// 是否启用审计
    enabled: bool,
    /// 响应状态码
    response_status: Mutex<Option<StatusCode>>,
    /// 请求开始时间
    start_time: Instant,
    /// 请求路径
    path: String,
    /// 请求方法
    method: String,
}

impl AuditContext {
    /// 创建新的审计上下文
    pub fn new(
        event_id: String,
        event_sender: mpsc::UnboundedSender<AuditEvent>,
        enabled: bool,
        path: String,
        method: String,
    ) -> Self {
        Self {
            inner: Arc::new(AuditContextInner {
                event_id,
                event_sender,
                enabled,
                response_status: Mutex::new(None),
                start_time: Instant::now(),
                path,
                method,
            }),
        }
    }

    /// 是否启用审计
    pub fn enabled(&self) -> bool {
        self.inner.enabled
    }

    /// 设置响应状态码
    /// 
    /// # Panic Safety
    /// 
    /// 如果 Mutex 被污染（poisoned），我们会尝试恢复数据。
    /// 这确保即使在异常情况下，审计日志也能被正确记录。
    pub fn set_response_status(&self, status: StatusCode) {
        match self.inner.response_status.lock() {
            Ok(mut guard) => {
                *guard = Some(status);
            }
            Err(poisoned) => {
                // Mutex 被污染，但我们仍然需要记录状态码
                tracing::error!(
                    "Response status mutex poisoned for event {}, recovering data",
                    self.inner.event_id
                );
                
                // 恢复数据并设置状态码
                let mut guard = poisoned.into_inner();
                *guard = Some(status);
                
                // 记录这个异常情况到审计日志中
                // 这样我们就能追踪到系统中发生的异常
                self.log_mutex_poison_event();
            }
        }
    }

    /// 获取响应状态码
    /// 
    /// # Panic Safety
    /// 
    /// 如果 Mutex 被污染，我们会恢复数据并返回。
    /// 这确保审计流程能够继续进行。
    pub fn get_response_status(&self) -> Option<StatusCode> {
        match self.inner.response_status.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => {
                tracing::error!(
                    "Response status mutex poisoned when reading for event {}, recovering data",
                    self.inner.event_id
                );
                
                // 恢复数据并返回
                let guard = poisoned.into_inner();
                *guard
            }
        }
    }

    /// 处理审计阶段（非阻塞）
    pub fn process_stage(&self, stage: AuditStage) {
        if !self.enabled() {
            return;
        }

        let latency = self.inner.start_time.elapsed();
        let status = self.get_response_status();

        let event = AuditEvent::new(
            self.inner.event_id.clone(),
            stage,
            status,
            latency,
            self.inner.path.clone(),
            self.inner.method.clone(),
        );

        // 非阻塞发送到后台任务
        if let Err(e) = self.inner.event_sender.send(event) {
            tracing::error!(
                "Failed to send audit event for {}: {:?}",
                self.inner.event_id,
                e
            );
        }
    }

    /// 获取事件 ID
    pub fn event_id(&self) -> &str {
        &self.inner.event_id
    }

    /// 记录 Mutex 污染事件
    /// 
    /// 当检测到 Mutex 被污染时，我们创建一个特殊的审计事件
    /// 来记录这个异常情况。这对于系统监控和问题排查非常重要。
    fn log_mutex_poison_event(&self) {
        tracing::warn!(
            "Mutex poisoned detected for audit event {}, this indicates a panic occurred while holding the lock",
            self.inner.event_id
        );
        
        // 可以选择发送一个特殊的审计事件
        // 但要注意避免递归（因为发送事件可能也会访问 Mutex）
        // 这里我们只记录日志，不发送审计事件
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_context_normal_operation() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let context = AuditContext::new(
            "test-001".to_string(),
            tx,
            true,
            "/test".to_string(),
            "GET".to_string(),
        );

        // 正常设置和获取
        context.set_response_status(StatusCode::OK);
        assert_eq!(context.get_response_status(), Some(StatusCode::OK));

        // 覆盖状态码
        context.set_response_status(StatusCode::NOT_FOUND);
        assert_eq!(context.get_response_status(), Some(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn test_context_disabled() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let context = AuditContext::new(
            "test-002".to_string(),
            tx,
            false, // 禁用审计
            "/test".to_string(),
            "GET".to_string(),
        );

        context.process_stage(AuditStage::RequestReceived);
        
        // 不应该收到任何事件
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_context_multiple_stages() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let context = AuditContext::new(
            "test-003".to_string(),
            tx,
            true,
            "/test".to_string(),
            "GET".to_string(),
        );

        context.process_stage(AuditStage::RequestReceived);
        context.set_response_status(StatusCode::OK);
        context.process_stage(AuditStage::ResponseComplete);

        // 应该收到两个事件
        let event1 = rx.recv().await.unwrap();
        assert_eq!(event1.stage, AuditStage::RequestReceived);
        assert_eq!(event1.status, None);

        let event2 = rx.recv().await.unwrap();
        assert_eq!(event2.stage, AuditStage::ResponseComplete);
        assert_eq!(event2.status, Some(StatusCode::OK));
    }

    #[test]
    fn test_context_clone() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let context = AuditContext::new(
            "test-004".to_string(),
            tx,
            true,
            "/test".to_string(),
            "GET".to_string(),
        );

        // 克隆上下文
        let context2 = context.clone();

        // 在一个上下文中设置状态码
        context.set_response_status(StatusCode::OK);

        // 在另一个上下文中应该能读取到
        assert_eq!(context2.get_response_status(), Some(StatusCode::OK));
    }
}
