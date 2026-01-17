//! 审计中间件实现

use crate::body::AuditResponseBody;
use crate::context::AuditContext;
use crate::guard::AuditGuard;
use crate::policy::{LongRunningCheck, PolicyEvaluator};
use crate::types::AuditStage;
use hyper::{Body, Request, Response, StatusCode};
use std::future::Future;
use std::sync::Arc;
use tokio::sync::mpsc;

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
pub async fn with_audit<F, Fut>(
    req: Request<Body>,
    handler: F,
    event_sender: mpsc::UnboundedSender<crate::types::AuditEvent>,
    policy: Arc<dyn PolicyEvaluator>,
    long_running_check: Option<LongRunningCheck>,
) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>>
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
        return handler(req).await;
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

            // 将 AuditResponseBody 包装为 Hyper 的 Body
            let wrapped_body = Body::wrap_body(audit_body);

            Ok(Response::from_parts(parts, wrapped_body))
        }
        Err(e) => {
            // 错误情况：设置错误状态
            context.set_response_status(StatusCode::INTERNAL_SERVER_ERROR);
            // guard 会在这里 drop，自动记录完成
            Err(e)
        }
    }
}
