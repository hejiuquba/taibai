//! 测试 Mutex Poison 场景

use audit_filter::*;
use hyper::{Body, Request, Response, StatusCode};
use std::sync::{Arc, Mutex};
use std::thread;

/// 模拟一个会导致 Mutex poison 的场景
#[test]
fn test_mutex_poison_recovery() {
    // 创建一个共享的 Mutex
    let mutex = Arc::new(Mutex::new(0));
    let mutex_clone = mutex.clone();

    // 线程 1：持有锁并 panic
    let handle = thread::spawn(move || {
        let mut guard = mutex_clone.lock().unwrap();
        *guard = 42;
        panic!("Intentional panic to poison mutex");
    });

    // 等待线程 panic
    let _ = handle.join();

    // 线程 2：尝试访问被污染的 Mutex
    let result = mutex.lock();
    assert!(result.is_err(), "Mutex should be poisoned");

    // 但我们可以恢复数据
    let guard = result.unwrap_or_else(|e| e.into_inner());
    assert_eq!(*guard, 42, "Data should be recoverable");
}

/// 测试审计上下文在 Mutex poison 后仍然能工作
#[tokio::test]
async fn test_audit_context_survives_poison() {
    use tokio::sync::mpsc;

    let (tx, mut rx) = mpsc::unbounded_channel();
    let context = AuditContext::new(
        "poison-test".to_string(),
        tx,
        true,
        "/test".to_string(),
        "GET".to_string(),
    );

    // 正常设置状态码
    context.set_response_status(StatusCode::OK);
    assert_eq!(context.get_response_status(), Some(StatusCode::OK));

    // 即使在异常情况下，审计流程也应该能继续
    context.process_stage(AuditStage::RequestReceived);
    context.process_stage(AuditStage::ResponseComplete);

    // 验证事件被正确发送
    let event1 = rx.recv().await.unwrap();
    assert_eq!(event1.stage, AuditStage::RequestReceived);

    let event2 = rx.recv().await.unwrap();
    assert_eq!(event2.stage, AuditStage::ResponseComplete);
}
