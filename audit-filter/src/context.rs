//! 审计上下文

use crate::types::{AuditEvent, AuditStage};
use hyper::StatusCode;
use parking_lot::Mutex;
use std::sync::Arc;
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
    pub fn set_response_status(&self, status: StatusCode) {
        *self.inner.response_status.lock() = Some(status);
    }

    /// 获取响应状态码
    pub fn get_response_status(&self) -> Option<StatusCode> {
        *self.inner.response_status.lock()
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
            tracing::error!("Failed to send audit event: {:?}", e);
        }
    }

    /// 获取事件 ID
    pub fn event_id(&self) -> &str {
        &self.inner.event_id
    }
}
