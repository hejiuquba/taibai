//! 审计中间件实现

use crate::body::AuditResponseBody;
use crate::context::AuditContext;
use crate::guard::AuditGuard;
use crate::policy::{LongRunningCheck, PolicyEvaluator};
use crate::types::{AuditStage, StatusCode};
use hyper::{Body, Request, Response};
use std::future::Future;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// 生成唯一事件ID（替代 uuid）
fn generate_event_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    
    // 添加一些随机性
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    
    let mut hasher = DefaultHasher::new();
    now.hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    
    format!("audit-{:x}", hasher.finish())
}

/// 将 hyper::StatusCode 转换为我们的 StatusCode
fn to_our_status_code(status: hyper::StatusCode) -> StatusCode {
    StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

/// 审计中间件
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

    // 生成唯一事件 ID（不使用 uuid）
    let event_id = generate_event_id();

    // 提取请求信息
    let path = req.uri().path().to_string();
    let method = req.method().to_string();

    // 创建审计上下文
    let context = AuditContext::new(event_id, event_sender, enabled, path, method);

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

            // 记录响应状态（转换为我们的 StatusCode）
            context.set_response_status(to_our_status_code(parts.status));

            // 包装 Body，在流结束时记录完成
            let audit_body = AuditResponseBody::new(body, context, guard, is_long_running);

            // 转换为标准 Body
            Ok(Response::from_parts(parts, Body::wrap_stream(audit_body)))
        }
        Err(e) => {
            // 错误情况：设置错误状态
            context.set_response_status(StatusCode::INTERNAL_SERVER_ERROR);
            // guard 会在这里 drop，自动记录完成
            Err(e)
        }
    }
}