//! 审计事件接收器

use crate::types::AuditEvent;
use std::sync::Arc;
use tokio::sync::mpsc;

/// 审计事件接收器 trait
pub trait AuditSink: Send + Sync {
    /// 处理审计事件（同步方法，由后台任务调用）
    fn process_event(&self, event: AuditEvent);
}

/// 控制台输出 Sink（用于测试）
pub struct ConsoleSink;

impl AuditSink for ConsoleSink {
    fn process_event(&self, event: AuditEvent) {
        println!(
            "[Audit] {} | {:?} | {} {} | Status: {:?} | Latency: {:?}",
            event.event_id,
            event.stage,
            event.method,
            event.path,
            event.status.map(|s| s.as_u16()),
            event.latency
        );
    }
}

/// 审计事件处理器（后台任务）
pub struct AuditProcessor {
    sender: mpsc::UnboundedSender<AuditEvent>,
}

impl AuditProcessor {
    /// 创建新的审计处理器，启动后台任务
    pub fn new(sink: Arc<dyn AuditSink>) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel();

        // 启动后台任务处理审计事件
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                sink.process_event(event);
            }
            eprintln!("[DEBUG] Audit processor task terminated");
        });

        Self { sender: tx }
    }

    /// 发送审计事件（非阻塞）
    pub fn send_event(&self, event: AuditEvent) {
        if let Err(e) = self.sender.send(event) {
            eprintln!("[ERROR] Failed to send audit event: {:?}", e);
        }
    }

    /// 获取发送器的克隆
    pub fn sender(&self) -> mpsc::UnboundedSender<AuditEvent> {
        self.sender.clone()
    }
}