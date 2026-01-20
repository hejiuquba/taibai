//! 响应体包装

use crate::context::AuditContext;
use crate::guard::AuditGuard;
use crate::types::{AuditStage, StatusCode};
use hyper::Body;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

/// 类型别名，隐藏 Bytes 的实际来源
type BodyData = hyper::body::Bytes;

/// 审计响应体包装
pub struct AuditResponseBody {
    inner: Body,
    context: AuditContext,
    _guard: AuditGuard,
    completed_flag: Arc<AtomicBool>,
    is_long_running: bool,
    first_chunk_sent: bool,
}

impl AuditResponseBody {
    pub fn new(
        inner: Body,
        context: AuditContext,
        guard: AuditGuard,
        is_long_running: bool,
    ) -> Self {
        let completed_flag = guard.completed_flag();
        Self {
            inner,
            context,
            _guard: guard,
            completed_flag,
            is_long_running,
            first_chunk_sent: false,
        }
    }
}

impl futures::Stream for AuditResponseBody {
    type Item = Result<BodyData, hyper::Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let inner = unsafe { Pin::new_unchecked(&mut self.inner) };
        let result = inner.poll_next(cx);

        if self.is_long_running && !self.first_chunk_sent {
            if let Poll::Ready(Some(Ok(_))) = &result {
                self.first_chunk_sent = true;
                self.context.process_stage(AuditStage::ResponseStarted);
            }
        }

        if let Poll::Ready(None) = &result {
            self.completed_flag.store(true, Ordering::SeqCst);
        }

        result
    }
}

impl Drop for AuditResponseBody {
    fn drop(&mut self) {
        self.completed_flag.store(true, Ordering::SeqCst);

        if std::thread::panicking() {
            eprintln!("[WARN] AuditResponseBody dropped due to panic: {}", self.context.event_id());
            self.context.set_response_status(StatusCode::INTERNAL_SERVER_ERROR);
            self.context.process_stage(AuditStage::Panic);
        } else {
            if self.context.get_response_status().is_none() {
                self.context.set_response_status(StatusCode::OK);
            }
            self.context.process_stage(AuditStage::ResponseComplete);
        }
    }
}