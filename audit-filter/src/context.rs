//! 审计上下文

use crate::types::{AuditEvent, AuditStage, StatusCode};
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
    pub fn set_response_status(&self, status: StatusCode) {
        match self.inner.response_status.lock() {
            Ok(mut guard) => {
                *guard = Some(status);
            }
            Err(poisoned) => {
                eprintln!("[ERROR] Response status mutex poisoned for event {}, recovering data", self.inner.event_id);
                let mut guard = poisoned.into_inner();
                *guard = Some(status);
                self.log_mutex_poison_event();
            }
        }
    }

    /// 获取响应状态码
    pub fn get_response_status(&self) -> Option<StatusCode> {
        match self.inner.response_status.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => {
                eprintln!("[ERROR] Response status mutex poisoned when reading for event {}, recovering data", self.inner.event_id);
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

        if let Err(e) = self.inner.event_sender.send(event) {
            eprintln!("[ERROR] Failed to send audit event for {}: {:?}", self.inner.event_id, e);
        }
    }

    /// 获取事件 ID
    pub fn event_id(&self) -> &str {
        &self.inner.event_id
    }

    fn log_mutex_poison_event(&self) {
        eprintln!("[WARN] Mutex poisoned detected for audit event {}, this indicates a panic occurred while holding the lock", self.inner.event_id);
    }
}

// 测试代码需要相应更新...