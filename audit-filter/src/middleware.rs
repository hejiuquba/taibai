//! 审计中间件实现

use crate::body::AuditResponseBody;
use crate::context::AuditContext;
use crate::guard::AuditGuard;
use crate::policy::{LongRunningCheck, PolicyEvaluator};
use crate::types::AuditStage;
use bytes::Bytes;
use http_body::Body as HttpBody;
use hyper::{Body, Request, Response, StatusCode};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tokio::sync::mpsc;

/// 审计响应体包装器
/// 
/// 这个 enum 允许我们在需要时包装响应体，在不需要时直接使用原始响应体
pub enum AuditResponseBodyWrapper {
    /// 未启用审计，直接使用原始 Body
    Plain(Body),
    /// 启用审计，使用包装的 AuditResponseBody
    Audited(AuditResponseBody),
}

impl HttpBody for AuditResponseBodyWrapper {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_data(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
        match &mut *self {
            AuditResponseBodyWrapper::Plain(body) => {
                let pinned = unsafe { Pin::new_unchecked(body) };
                pinned.poll_data(cx)
            }
            AuditResponseBodyWrapper::Audited(audit_body) => {
                let pinned = unsafe { Pin::new_unchecked(audit_body) };
                pinned.poll_data(cx)
            }
        }
    }

    fn poll_trailers(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Option<http::HeaderMap>, Self::Error>> {
        match &mut *self {
            AuditResponseBodyWrapper::Plain(body) => {
                let pinned = unsafe { Pin::new_unchecked(body) };
                pinned.poll_trailers(cx)
            }
            AuditResponseBodyWrapper::Audited(audit_body) => {
                let pinned = unsafe { Pin::new_unchecked(audit_body) };
                pinned.poll_trailers(cx)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            AuditResponseBodyWrapper::Plain(body) => body.is_end_stream(),
            AuditResponseBodyWrapper::Audited(audit_body) => audit_body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            AuditResponseBodyWrapper::Plain(body) => body.size_hint(),
            AuditResponseBodyWrapper::Audited(audit_body) => audit_body.size_hint(),
        }
    }
}

/// 审计中间件
/// 
/// # 参数
/// - `req`: HTTP 请求
/// - `handler`: 业务处理函数（返回 Future）
/// - `event_sender`: 审计事件发送器
/// - `policy`: 审计策略评估器
/// - `long_running_check`: 可选的长请求检查函数
/// 
/// # 返回
/// 包装后的响应，确保审计日志被正确记录
/// 
/// # 注意
/// 返回的 Response 使用 `AuditResponseBodyWrapper` 作为 Body 类型。
/// 如果需要转换为标准的 `Response<Body>`，需要进行类型转换。
pub async fn with_audit<F, Fut>(
    req: Request<Body>,
    handler: F,
    event_sender: mpsc::UnboundedSender<crate::types::AuditEvent>,
    policy: Arc<dyn PolicyEvaluator>,
    long_running_check: Option<LongRunningCheck>,
) -> Result<Response<AuditResponseBodyWrapper>, Box<dyn std::error::Error + Send + Sync>>
where
    F: FnOnce(Request<Body>) -> Fut,
    Fut: Future<Output = Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>>>,
{
    // 1. 评估策略
    let enabled = policy.evaluate(&req);

    // 生成唯一事件 ID
    let event_id = uuid::Uuid::new_v4().to_string();

    // 提取请求信息
    let path = req.uri().path().to_string();
    let method = req.method().to_string();

    // 创建审计上下文
    let context = AuditContext::new(event_id.clone(), event_sender, enabled, path, method);

    // 如果不需要审计，直接执行业务逻辑
    if !enabled {
        let response = handler(req).await?;
        let (parts, body) = response.into_parts();
        return Ok(Response::from_parts(parts, AuditResponseBodyWrapper::Plain(body)));
    }

    // 2. 记录请求接收阶段
    context.process_stage(AuditStage::RequestReceived);

    // 3. 判断是否为长时间运行请求
    let is_long_running = long_running_check
        .as_ref()
        .map(|check| check(&req))
        .unwrap_or(false);

    // 4. 创建审计守卫（Drop 时自动记录完成）
    let guard = AuditGuard::new(context.clone());

    // 5. 执行业务逻辑
    let result = handler(req).await;

    // 6. 处理响应
    match result {
        Ok(response) => {
            let (parts, body) = response.into_parts();

            // 记录响应状态
            context.set_response_status(parts.status);

            // 如果是长请求，记录 ResponseStarted
            if is_long_running {
                context.process_stage(AuditStage::ResponseStarted);
            }

            // 包装 Body，在流结束时记录完成
            let audit_body = AuditResponseBody::new(body, context.clone(), guard, is_long_running);

            Ok(Response::from_parts(parts, AuditResponseBodyWrapper::Audited(audit_body)))
        }
        Err(e) => {
            // 错误情况：设置错误状态
            context.set_response_status(StatusCode::INTERNAL_SERVER_ERROR);
            // guard 会在这里 drop，自动记录完成
            Err(e)
        }
    }
}

/// 将 AuditResponseBodyWrapper 转换为标准的 Hyper Body
/// 
/// 这个辅助函数用于在需要时将我们的包装类型转换回 Hyper 的 Body
pub fn to_hyper_body(wrapper: AuditResponseBodyWrapper) -> Body {
    match wrapper {
        AuditResponseBodyWrapper::Plain(body) => body,
        AuditResponseBodyWrapper::Audited(audit_body) => {
            // 使用 wrap_stream 将 AuditResponseBody 转换为 Body
            Body::wrap_stream(AuditBodyStream { inner: Some(audit_body) })
        }
    }
}

/// Stream 适配器，用于将 AuditResponseBody 转换为 Stream
struct AuditBodyStream {
    inner: Option<AuditResponseBody>,
}

impl futures::Stream for AuditBodyStream {
    type Item = Result<Bytes, hyper::Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Self::Item>> {
        if let Some(ref mut inner) = self.inner {
            let pinned = unsafe { Pin::new_unchecked(inner) };
            match pinned.poll_data(cx) {
                Poll::Ready(Some(result)) => Poll::Ready(Some(result)),
                Poll::Ready(None) => {
                    // 流结束，移除 inner 以触发 Drop
                    self.inner = None;
                    Poll::Ready(None)
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(None)
        }
    }
}
