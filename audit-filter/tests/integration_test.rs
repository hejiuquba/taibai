use audit_filter::*;
use hyper::{Body, Request, Response, StatusCode};
use std::sync::Arc;
use tokio::sync::mpsc;

async fn simple_handler(
    _req: Request<Body>,
) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(Response::new(Body::from("OK")))
}

async fn error_handler(
    _req: Request<Body>,
) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
    Err("Error".into())
}

#[tokio::test]
async fn test_normal_request() {
    let sink = Arc::new(ConsoleSink);
    let processor = AuditProcessor::new(sink);
    let policy = Arc::new(AlwaysAuditPolicy);

    let req = Request::builder()
        .uri("http://localhost/test")
        .body(Body::empty())
        .unwrap();

    let result = with_audit(req, simple_handler, processor.sender(), policy, None).await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // 等待审计事件处理
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn test_error_request() {
    let sink = Arc::new(ConsoleSink);
    let processor = AuditProcessor::new(sink);
    let policy = Arc::new(AlwaysAuditPolicy);

    let req = Request::builder()
        .uri("http://localhost/error")
        .body(Body::empty())
        .unwrap();

    let result = with_audit(req, error_handler, processor.sender(), policy, None).await;

    assert!(result.is_err());

    // 等待审计事件处理
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn test_policy_disabled() {
    struct NeverAuditPolicy;
    impl PolicyEvaluator for NeverAuditPolicy {
        fn evaluate(&self, _req: &Request<Body>) -> bool {
            false
        }
    }

    let sink = Arc::new(ConsoleSink);
    let processor = AuditProcessor::new(sink);
    let policy = Arc::new(NeverAuditPolicy);

    let req = Request::builder()
        .uri("http://localhost/test")
        .body(Body::empty())
        .unwrap();

    let result = with_audit(req, simple_handler, processor.sender(), policy, None).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_long_running_request() {
    let sink = Arc::new(ConsoleSink);
    let processor = AuditProcessor::new(sink);
    let policy = Arc::new(AlwaysAuditPolicy);

    let long_check: LongRunningCheck = Box::new(|req| req.uri().path().contains("/watch"));

    let req = Request::builder()
        .uri("http://localhost/watch")
        .body(Body::empty())
        .unwrap();

    let result = with_audit(req, simple_handler, processor.sender(), policy, Some(long_check)).await;

    assert!(result.is_ok());

    // 等待审计事件处理
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
}
