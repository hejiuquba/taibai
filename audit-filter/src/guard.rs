//! 审计守卫 - 利用 Drop 保证审计日志一定被记录

use crate::context::AuditContext;
use crate::types::{AuditStage, StatusCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// 审计守卫
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
        if self.is_completed() {
            return;
        }

        if let Some(context) = self.context.take() {
            if std::thread::panicking() {
                eprintln!("[WARN] Audit guard dropped due to panic: {}", context.event_id());
                context.set_response_status(StatusCode::INTERNAL_SERVER_ERROR);
                context.process_stage(AuditStage::Panic);
            } else {
                if context.get_response_status().is_none() {
                    context.set_response_status(StatusCode::OK);
                }
                context.process_stage(AuditStage::ResponseComplete);
            }
        }
    }
}