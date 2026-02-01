// k8s-audit-plugins/src/fake/mod.rs

//! 假后端插件
//!
//! 这个模块提供了一个用于测试的假审计后端。
//! 它主要用于单元测试和集成测试，允许测试代码通过回调函数
//! 捕获和处理审计事件，而不需要实际的后端存储。

use std::sync::{Arc, Mutex};
use std::sync::mpsc;

use k8s_audit_apis::audit as audit_internal;
use k8s_audit_core::types::{Backend, BackendError, Sink};

/// 假后端结构体
///
/// 这个后端主要用于测试目的。它允许通过回调函数处理事件，
/// 而不实际存储或发送它们。
pub struct FakeBackend {
    /// 事件处理回调函数
    /// 当有事件到达时，会调用此回调函数
    on_request: Option<Arc<Mutex<dyn FnMut(&[Arc<audit_internal::Event>]) + Send + Sync>>>,
}

impl FakeBackend {
    /// 创建一个新的假后端
    pub fn new() -> Self {
        Self { on_request: None }
    }
    
    /// 创建一个带回调函数的假后端
    ///
    /// # 参数
    /// - `callback`: 事件处理回调函数，当有事件到达时会被调用
    pub fn with_callback<F>(callback: F) -> Self 
    where
        F: FnMut(&[Arc<audit_internal::Event>]) + Send + Sync + 'static,
    {
        Self {
            on_request: Some(Arc::new(Mutex::new(callback))),
        }
    }
    
    /// 设置或更新回调函数
    pub fn set_callback<F>(&mut self, callback: F)
    where
        F: FnMut(&[Arc<audit_internal::Event>]) + Send + Sync + 'static,
    {
        self.on_request = Some(Arc::new(Mutex::new(callback)));
    }
    
    /// 清除回调函数
    pub fn clear_callback(&mut self) {
        self.on_request = None;
    }
}

impl Default for FakeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Sink for FakeBackend {
    fn process_events(&self, events: &[Arc<audit_internal::Event>]) -> bool {
        // 如果有回调函数，调用它
        if let Some(callback) = &self.on_request {
            // 锁定回调函数并调用
            let mut callback_guard = match callback.lock() {
                Ok(guard) => guard,
                Err(_) => return true, // 如果无法获取锁，仍然返回成功
            };
            
            (*callback_guard)(events);
        }
        
        // 假后端总是返回成功
        true
    }
}

impl Backend for FakeBackend {
    fn run(&self, stop_rx: mpsc::Receiver<()>) -> Result<(), BackendError> {
        // 假后端不需要运行任何后台任务
        // 但我们可以监听停止信号，尽管我们不需要它
        std::thread::spawn(move || {
            let _ = stop_rx.recv();
            // 收到停止信号，不做任何事情
        });
        
        Ok(())
    }
    
    fn shutdown(&self) {
        // 假后端不需要关闭任何资源
    }
    
    fn name(&self) -> &str {
        "fake"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_audit_apis::audit::{Event, Stage};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    
    #[test]
    fn test_fake_backend_without_callback() {
        // 测试没有回调函数的假后端
        let backend = FakeBackend::new();
        
        let event = Arc::new(Event {
            audit_id: "test-1".to_string(),
            stage: Stage::RequestReceived,
            ..Default::default()
        });
        
        // 应该成功处理事件，即使没有回调函数
        let success = backend.process_events(&[event]);
        assert!(success, "没有回调函数时也应该返回成功");
    }
    
    #[test]
    fn test_fake_backend_with_callback() {
        // 测试有回调函数的假后端
        let event_count = Arc::new(AtomicUsize::new(0));
        let event_count_clone = Arc::clone(&event_count);
        
        let backend = FakeBackend::with_callback(move |events| {
            // 记录接收到的event数量
            event_count_clone.fetch_add(events.len(), Ordering::SeqCst);
        });
        
        let event1 = Arc::new(Event {
            audit_id: "test-2".to_string(),
            ..Default::default()
        });
        
        let event2 = Arc::new(Event {
            audit_id: "test-3".to_string(),
            ..Default::default()
        });
        
        // 处理单个事件
        let success = backend.process_events(&[event1]);
        assert!(success, "处理事件应该成功");
        assert_eq!(event_count.load(Ordering::SeqCst), 1, "应该记录1个事件");
        
        // 处理多个事件
        let event3 = Arc::new(Event {
            audit_id: "test-4".to_string(),
            ..Default::default()
        });
        
        let event4 = Arc::new(Event {
            audit_id: "test-5".to_string(),
            ..Default::default()
        });
        
        let success = backend.process_events(&[event3, event4]);
        assert!(success, "处理多个事件应该成功");
        assert_eq!(event_count.load(Ordering::SeqCst), 3, "应该总共记录3个事件");
    }
    
    #[test]
    fn test_fake_backend_set_callback() {
        // 测试动态设置回调函数
        let mut backend = FakeBackend::new();
        
        let first_callback_count = Arc::new(AtomicUsize::new(0));
        let first_count_clone = Arc::clone(&first_callback_count);
        
        // 设置第一个回调函数
        backend.set_callback(move |events| {
            first_count_clone.fetch_add(events.len(), Ordering::SeqCst);
        });
        
        let event1 = Arc::new(Event {
            audit_id: "test-6".to_string(),
            ..Default::default()
        });
        
        backend.process_events(&[event1]);
        assert_eq!(first_callback_count.load(Ordering::SeqCst), 1, "第一个回调应该被调用");
        
        // 设置第二个回调函数
        let second_callback_count = Arc::new(AtomicUsize::new(0));
        let second_count_clone = Arc::clone(&second_callback_count);
        
        backend.set_callback(move |events| {
            second_count_clone.fetch_add(events.len(), Ordering::SeqCst);
        });
        
        let event2 = Arc::new(Event {
            audit_id: "test-7".to_string(),
            ..Default::default()
        });
        
        backend.process_events(&[event2]);
        
        // 第一个回调不应该再被调用
        assert_eq!(first_callback_count.load(Ordering::SeqCst), 1, "第一个回调不应该再被调用");
        // 第二个回调应该被调用
        assert_eq!(second_callback_count.load(Ordering::SeqCst), 1, "第二个回调应该被调用");
    }
    
    #[test]
    fn test_fake_backend_clear_callback() {
        // 测试清除回调函数
        let mut backend = FakeBackend::new();
        
        let callback_count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&callback_count);
        
        backend.set_callback(move |events| {
            count_clone.fetch_add(events.len(), Ordering::SeqCst);
        });
        
        let event1 = Arc::new(Event {
            audit_id: "test-8".to_string(),
            ..Default::default()
        });
        
        backend.process_events(&[event1]);
        assert_eq!(callback_count.load(Ordering::SeqCst), 1, "回调应该被调用");
        
        // 清除回调
        backend.clear_callback();
        
        let event2 = Arc::new(Event {
            audit_id: "test-9".to_string(),
            ..Default::default()
        });
        
        let success = backend.process_events(&[event2]);
        assert!(success, "清除回调后处理事件应该仍然成功");
        
        // 回调计数不应该增加
        assert_eq!(callback_count.load(Ordering::SeqCst), 1, "清除回调后计数不应该增加");
    }
    
    #[test]
    fn test_fake_backend_name() {
        let backend = FakeBackend::new();
        assert_eq!(backend.name(), "fake", "后端名称应该是'fake'");
    }
    
    #[test]
    fn test_fake_backend_run_and_shutdown() {
        let backend = FakeBackend::new();
        
        // 测试run方法
        let (tx, rx) = mpsc::channel();
        let result = backend.run(rx);
        assert!(result.is_ok(), "run方法应该成功");
        
        // 发送停止信号
        tx.send(()).unwrap();
        
        // 测试shutdown方法（应该什么都不做）
        backend.shutdown();
    }
    
    #[test]
    fn test_fake_backend_event_data() {
        // 测试回调函数能正确访问事件数据
        let captured_id = Arc::new(Mutex::new(String::new()));
        let captured_id_clone = Arc::clone(&captured_id);
        
        let backend = FakeBackend::with_callback(move |events| {
            if let Some(event) = events.first() {
                let mut guard = captured_id_clone.lock().unwrap();
                *guard = event.audit_id.clone();
            }
        });
        
        let test_event = Arc::new(Event {
            audit_id: "unique-test-id-123".to_string(),
            stage: Stage::ResponseComplete,
            verb: "create".to_string(),
            request_uri: "/api/v1/pods".to_string(),
            ..Default::default()
        });
        
        backend.process_events(&[test_event]);
        
        let captured = captured_id.lock().unwrap();
        assert_eq!(*captured, "unique-test-id-123", "回调应该能访问事件数据");
    }
}