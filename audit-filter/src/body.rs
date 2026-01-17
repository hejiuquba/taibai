//! 响应体包装 - 用于拦截响应流并记录完成阶段

use crate::context::AuditContext;
use crate::guard::AuditGuard;
use crate::types::AuditStage;
use bytes::Bytes;
use http_body::Body as HttpBody;
use hyper::{Body, StatusCode};
use pin_project::pin_project;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

/// 审计响应体包装
/// 
/// 包装 Hyper 的 Body，用于：
/// 1. 检测长请求的首次数据发送
/// 2. 在流结束时记录完成阶段
#[pin_project]
pub struct AuditResponseBody {
    #[pin]
    inner: Body,
    context: AuditContext,
    _guard: AuditGuard,
    completed_flag: Arc<AtomicBool>,
    is_long_running: bool,
    first_chunk_sent: bool,
}

impl AuditResponseBody {
    /// 创建新的审计响应体
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

impl HttpBody for AuditResponseBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_data(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
        let this = self.project();

        // 转发到内部 Body
        let result = this.inner.poll_data(cx);

        // 检测长请求的首次数据（可选：在这里记录 ResponseStarted）
        if *this.is_long_running && !*this.first_chunk_sent {
            if let Poll::Ready(Some(Ok(_))) = &result {
                *this.first_chunk_sent = true;
                // 注意：我们已经在 middleware 中记录了 ResponseStarted
                // 如果需要在实际发送数据时才记录，可以在这里调用
                // this.context.process_stage(AuditStage::ResponseStarted);
            }
        }

        result
    }

    fn poll_trailers(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<http::HeaderMap>, Self::Error>> {
        let this = self.project();
        this.inner.poll_trailers(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for AuditResponseBody {
    fn drop(&mut self) {
        // 标记守卫为已完成
        self.completed_flag.store(true, Ordering::SeqCst);

        // 检查是否是 panic 导致的 drop
        if std::thread::panicking() {
            tracing::warn!(
                "AuditResponseBody dropped due to panic: {}",
                self.context.event_id()
            );
            self.context
                .set_response_status(StatusCode::INTERNAL_SERVER_ERROR);
            self.context.process_stage(AuditStage::Panic);
        } else {
            // 正常完成：Body 流结束
            if self.context.get_response_status().is_none() {
                self.context.set_response_status(StatusCode::OK);
            }
            self.context.process_stage(AuditStage::ResponseComplete);
        }
    }
}
