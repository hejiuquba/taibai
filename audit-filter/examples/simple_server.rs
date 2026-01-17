//! 简单的 HTTP 服务器示例，演示如何使用审计中间件

use audit_filter::*;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use std::convert::Infallible;
use std::sync::Arc;

/// 业务 Handler
async fn handle_request(
    req: Request<Body>,
) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
    let path = req.uri().path();

    match path {
        "/hello" => {
            // 正常请求
            Ok(Response::new(Body::from("Hello, World!")))
        }
        "/slow" => {
            // 模拟慢请求
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            Ok(Response::new(Body::from("Slow response")))
        }
        "/error" => {
            // 错误请求
            Err("Intentional error".into())
        }
        "/panic" => {
            // Panic 请求（注意：在实际环境中 panic 会导致线程崩溃）
            // 这里仅用于演示审计机制
            panic!("Intentional panic!");
        }
        "/watch" => {
            // 长时间运行请求
            let body = Body::from("Watching...");
            Ok(Response::new(body))
        }
        _ => {
            let mut response = Response::new(Body::from("Not Found"));
            *response.status_mut() = StatusCode::NOT_FOUND;
            Ok(response)
        }
    }
}

#[tokio::main]
async fn main() {
    // 初始化日志
    tracing_subscriber::fmt::init();

    // 1. 创建审计 Sink
    let sink = Arc::new(ConsoleSink);

    // 2. 创建审计处理器（启动后台任务）
    let processor = AuditProcessor::new(sink);
    let event_sender = processor.sender();

    // 3. 创建审计策略
    let policy: Arc<dyn PolicyEvaluator> = Arc::new(AlwaysAuditPolicy);

    // 4. 定义长请求检查函数
    let long_running_check: Option<LongRunningCheck> =
        Some(Box::new(default_long_running_check));

    // 5. 创建服务
    let make_svc = make_service_fn(move |_conn| {
        let event_sender = event_sender.clone();
        let policy = policy.clone();
        let long_running_check = long_running_check.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let event_sender = event_sender.clone();
                let policy = policy.clone();
                let long_running_check = long_running_check.clone();

                async move {
                    // 使用审计中间件包装请求
                    let result = with_audit(
                        req,
                        handle_request,
                        event_sender,
                        policy,
                        long_running_check,
                    )
                    .await;

                    // 将错误转换为 HTTP 响应
                    match result {
                        Ok(response) => Ok::<_, Infallible>(response),
                        Err(e) => {
                            eprintln!("Handler error: {}", e);
                            let mut response = Response::new(Body::from(format!("Error: {}", e)));
                            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                            Ok(response)
                        }
                    }
                }
            }))
        }
    });

    // 6. 启动服务器
    let addr = ([127, 0, 0, 1], 3000).into();
    let server = Server::bind(&addr).serve(make_svc);

    println!("Listening on http://{}", addr);
    println!("\nTry these endpoints:");
    println!("  curl http://localhost:3000/hello");
    println!("  curl http://localhost:3000/slow");
    println!("  curl http://localhost:3000/error");
    println!("  curl http://localhost:3000/watch");
    println!("  curl http://localhost:3000/notfound");

    if let Err(e) = server.await {
        eprintln!("Server error: {}", e);
    }
}
