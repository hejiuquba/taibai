//! 审计守卫 - 利用 Drop 保证审计日志一定被记录

use crate::context::AuditContext;
use crate::types::AuditStage;
use hyper::StatusCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// 审计守卫
/// 
/// 利用 RAII 机制，确保在任何情况下（正常返回、错误、panic）
/// 都会记录审计日志
pub struct AuditGuard {
    context: Option<AuditContext>,
    completed: Arc<AtomicBool>,
}

impl AuditGuard {
    /// 创建新的审计守卫
    pub fn new(context: AuditContext) -> Self {
        Self {
            context: Some(context),
            completed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 标记为已完成（避免 Drop 时重复记录）
    pub fn mark_completed(&self) {
        self.completed.store(true, Ordering::SeqCst);
    }

    /// 检查是否已完成
    pub fn is_completed(&self) -> bool {
        self.completed.load(Ordering::SeqCst)
    }

    /// 获取审计上下文的引用
    pub fn context(&self) -> &AuditContext {
        self.context.as_ref().expect("AuditGuard context is None")
    }

    /// 获取完成标志的克隆（用于传递给 Body）
    pub fn completed_flag(&self) -> Arc<AtomicBool> {
        self.completed.clone()
    }
}

impl Drop for AuditGuard {
    fn drop(&mut self) {
        // 如果已经正常完成，不需要再记录
        if self.is_completed() {
            return;
        }

        if let Some(context) = self.context.take() {
            // 检查是否是 panic 导致的 drop
            if std::thread::panicking() {
                tracing::warn!(
                    "Audit guard dropped due to panic: {}",
                    context.event_id()
                );
                context.set_response_status(StatusCode::INTERNAL_SERVER_ERROR);
                context.process_stage(AuditStage::Panic);
            } else {
                // 正常情况但没有标记完成（可能是连接提前关闭或错误返回）
                if context.get_response_status().is_none() {
                    context.set_response_status(StatusCode::OK);
                }
                context.process_stage(AuditStage::ResponseComplete);
            }
        }
    }
}
