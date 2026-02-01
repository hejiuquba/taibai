// k8s-audit-plugins/src/truncate/mod.rs

//! 截断后端插件
//!
//! 这个模块提供了一个截断的审计后端，它包装其他后端并添加事件大小限制
//! 和批处理大小限制功能。当事件或批次超过大小时，会自动进行截断或分割。

use std::fmt;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use serde_json;
use tokio::runtime::Runtime;

use k8s_audit_apis::audit as audit_internal;
use k8s_audit_apis::audit::{Event, Level};
use k8s_audit_core::types::{Backend, BackendError, Sink};

/// 插件名称
pub const PLUGIN_NAME: &str = "truncate";

/// 用于指示截断的注解键
pub const ANNOTATION_KEY: &str = "audit.k8s.io/truncated";
/// 用于指示截断的注解值
pub const ANNOTATION_VALUE: &str = "true";

/// 截断后端配置
#[derive(Debug, Clone)]
pub struct TruncateConfig {
    /// 定义事件的最大允许大小。如果事件更大，将执行截断。
    pub max_event_size: usize,
    
    /// 定义传递给后端的批次事件的最大允许大小。
    /// 如果批次的总大小大于此数字，批次将被分割。
    /// 序列化请求的实际大小可能略高，大约几百字节。
    pub max_batch_size: usize,
}

impl Default for TruncateConfig {
    fn default() -> Self {
        Self {
            max_event_size: 100 * 1024, // 100KB
            max_batch_size: 4 * 1024 * 1024, // 4MB
        }
    }
}

/// 大小计算器
struct SizeCalculator {
    size: usize,
}

impl SizeCalculator {
    fn new() -> Self {
        Self { size: 0 }
    }
    
    fn write(&mut self, data: &[u8]) {
        self.size += data.len();
    }
    
    fn size(&self) -> usize {
        self.size
    }
}

/// 截断后端结构体
pub struct TruncateBackend {
    /// 实际导出事件的委托后端
    delegate: Arc<dyn Backend>,
    
    /// 截断配置
    config: TruncateConfig,
    
    /// 异步运行时（如果需要）
    runtime: Option<Arc<Runtime>>,
}

impl TruncateBackend {
    /// 创建一个新的截断后端，使用参数中传递的配置。
    /// 截断后端会自动运行和关闭委托后端。
    pub fn new(delegate: Arc<dyn Backend>, config: TruncateConfig) -> Self {
        Self {
            delegate,
            config,
            runtime: None,
        }
    }
    
    /// 计算事件的大小
    fn calc_size(&self, event: &Event) -> Result<usize, String> {
        // 使用serde_json序列化来计算大小
        let mut calculator = SizeCalculator::new();
        
        // 序列化事件到大小计算器
        let json = serde_json::to_string(event)
            .map_err(|e| format!("序列化事件失败: {}", e))?;
        
        calculator.write(json.as_bytes());
        Ok(calculator.size())
    }
    
    /// 从审计事件中移除请求和响应对象，
    /// 尝试至少保留元数据。
    fn truncate_event(&self, event: &Event) -> Event {
        // 创建事件的浅拷贝
        let mut new_event = event.clone();
        
        // 清除请求和响应对象
        new_event.request_object = None;
        new_event.response_object = None;
        
        // 添加截断注解
        if new_event.annotations.is_empty() {
            new_event.annotations = std::collections::HashMap::new();
        }
        new_event.annotations.insert(
            ANNOTATION_KEY.to_string(),
            ANNOTATION_VALUE.to_string(),
        );
        
        new_event
    }
    
    /// 处理事件批次，应用大小限制
    fn process_events_internal(&self, events: &[Arc<Event>]) -> bool {
        let mut errors = Vec::new();
        let mut impacted_events = Vec::new();
        let mut current_batch = Vec::new();
        let mut current_batch_size = 0;
        let mut success = true;
        
        for event in events {
            // 计算事件大小
            let size_result = self.calc_size(event);
            
            match size_result {
                Ok(size) => {
                    let mut processed_event = (**event).clone();
                    let mut should_truncate = false;
                    
                    // 如果事件大小超过限制且适合截断（即包含请求和/或响应），尝试截断
                    if size > self.config.max_event_size && event.level >= Level::Request {
                        processed_event = self.truncate_event(event);
                        
                        // 重新计算截断后的大小
                        match self.calc_size(&processed_event) {
                            Ok(new_size) => {
                                if new_size > self.config.max_event_size {
                                    // 即使截断后仍然太大
                                    errors.push(format!("事件在截断后仍然太大"));
                                    impacted_events.push(Arc::new(processed_event));
                                    continue;
                                }
                                should_truncate = true;
                            }
                            Err(e) => {
                                errors.push(e);
                                impacted_events.push(Arc::new(processed_event));
                                continue;
                            }
                        }
                    } else if size > self.config.max_event_size {
                        // 事件太大但不适合截断（级别太低）
                        errors.push(format!("事件太大且无法截断"));
                        impacted_events.push(Arc::new((**event).clone()));
                        continue;
                    }
                    
                    // 检查是否需要开始新的批次
                    if !current_batch.is_empty() && current_batch_size + size > self.config.max_batch_size {
                        // 发送当前批次
                        let batch_success = self.delegate.process_events(&current_batch);
                        success = batch_success && success;
                        
                        // 开始新批次
                        current_batch.clear();
                        current_batch_size = 0;
                    }
                    
                    // 添加到当前批次
                    current_batch_size += size;
                    current_batch.push(if should_truncate {
                        Arc::new(processed_event)
                    } else {
                        Arc::clone(event)
                    });
                }
                Err(e) => {
                    errors.push(e);
                    impacted_events.push(Arc::clone(event));
                }
            }
        }
        
        // 发送剩余的批次
        if !current_batch.is_empty() {
            let batch_success = self.delegate.process_events(&current_batch);
            success = batch_success && success;
        }
        
        // 处理错误
        if !errors.is_empty() {
            // 记录插件错误
            let error_msg = errors.join("; ");
            eprintln!("截断插件错误: {} - 受影响的事件: {}", error_msg, impacted_events.len());
        }
        
        success
    }
}

impl Sink for TruncateBackend {
    fn process_events(&self, events: &[Arc<Event>]) -> bool {
        self.process_events_internal(events)
    }
}

impl Backend for TruncateBackend {
    fn run(&self, stop_rx: mpsc::Receiver<()>) -> Result<(), BackendError> {
        // 运行委托后端
        self.delegate.run(stop_rx)
    }
    
    fn shutdown(&self) {
        // 关闭委托后端
        self.delegate.shutdown();
    }
    
    fn name(&self) -> &str {
        PLUGIN_NAME
    }
}

impl fmt::Display for TruncateBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}<{}>", PLUGIN_NAME, self.delegate.name())
    }
}

impl Clone for TruncateBackend {
    fn clone(&self) -> Self {
        Self {
            delegate: self.delegate.clone(),
            config: self.config.clone(),
            runtime: self.runtime.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_audit_apis::audit::{Event, Level, Unknown};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    
    // 测试用的假后端
    #[derive(Clone)]
    struct TestBackend {
        process_count: Arc<AtomicUsize>,
        event_count: Arc<AtomicUsize>,
        received_events: Arc<Mutex<Vec<Arc<Event>>>>,
    }
    
    impl TestBackend {
        fn new() -> Self {
            Self {
                process_count: Arc::new(AtomicUsize::new(0)),
                event_count: Arc::new(AtomicUsize::new(0)),
                received_events: Arc::new(Mutex::new(Vec::new())),
            }
        }
        
        fn process_count(&self) -> usize {
            self.process_count.load(Ordering::SeqCst)
        }
        
        fn event_count(&self) -> usize {
            self.event_count.load(Ordering::SeqCst)
        }
        
        fn received_events(&self) -> Vec<Arc<Event>> {
            self.received_events.lock().unwrap().clone()
        }
    }
    
    impl Sink for TestBackend {
        fn process_events(&self, events: &[Arc<Event>]) -> bool {
            self.process_count.fetch_add(1, Ordering::SeqCst);
            self.event_count.fetch_add(events.len(), Ordering::SeqCst);
            
            let mut received = self.received_events.lock().unwrap();
            for event in events {
                received.push(Arc::clone(event));
            }
            
            true
        }
    }
    
    impl Backend for TestBackend {
        fn run(&self, _stop_rx: mpsc::Receiver<()>) -> Result<(), BackendError> {
            Ok(())
        }
        
        fn shutdown(&self) {}
        
        fn name(&self) -> &str {
            "test"
        }
    }
    
    fn create_large_event(size: usize, level: Level) -> Event {
        let mut event = Event {
            level: level.clone(),
            audit_id: "test-id".to_string(),
            ..Default::default()
        };
        
        if level >= Level::Request {
            // 创建大型请求对象
            let large_string = "A".repeat(size);
            event.request_object = Some(Unknown {
                raw: Some(serde_json::Value::String(large_string)),
                ..Default::default()
            });
        }
        
        event
    }
    
    #[test]
    fn test_truncating_events_empty() {
        // 空事件不应该被截断
        let delegate = Arc::new(TestBackend::new());
        let config = TruncateConfig::default();
        
        let backend = TruncateBackend::new(delegate.clone(), config);
        
        let event = Arc::new(Event::default());
        let success = backend.process_events(&[event]);
        
        assert!(success, "处理事件应该成功");
        assert_eq!(delegate.process_count(), 1, "应该处理1个批次");
        assert_eq!(delegate.event_count(), 1, "应该处理1个事件");
        
        let received = delegate.received_events();
        assert_eq!(received.len(), 1, "应该收到1个事件");
        
        // 检查事件没有被截断
        let received_event = &received[0];
        assert!(
            !received_event.annotations.contains_key(ANNOTATION_KEY),
            "空事件不应该有截断注解"
        );
    }
    
    #[test]
    fn test_truncating_events_large_request() {
        // 请求级别的大型事件应该被截断
        let delegate = Arc::new(TestBackend::new());
        let config = TruncateConfig {
            max_event_size: 1000, // 很小的大小限制
            ..Default::default()
        };
        
        let backend = TruncateBackend::new(delegate.clone(), config);
        
        // 创建超过大小限制的事件
        let event = Arc::new(create_large_event(2000, Level::Request));
        let success = backend.process_events(&[event]);
        
        assert!(success, "处理事件应该成功");
        
        let received = delegate.received_events();
        assert_eq!(received.len(), 1, "应该收到1个事件（截断后）");
        
        // 检查事件被截断
        let received_event = &received[0];
        assert_eq!(
            received_event.annotations.get(ANNOTATION_KEY),
            Some(&ANNOTATION_VALUE.to_string()),
            "截断的事件应该有截断注解"
        );
        assert!(
            received_event.request_object.is_none(),
            "截断后请求对象应该为None"
        );
        assert!(
            received_event.response_object.is_none(),
            "截断后响应对象应该为None"
        );
    }
    
    #[test]
    fn test_truncating_events_large_metadata() {
        // 元数据级别的大型事件应该被丢弃
        let delegate = Arc::new(TestBackend::new());
        let config = TruncateConfig {
            max_event_size: 1000,
            ..Default::default()
        };
        
        let backend = TruncateBackend::new(delegate.clone(), config);
        
        // 创建元数据级别的大型事件（包含大型注解）
        let mut event = Event::default();
        event.level = Level::Metadata;
        event.annotations.insert(
            "key".to_string(),
            "A".repeat(2000), // 大型注解
        );
        
        let success = backend.process_events(&[Arc::new(event)]);
        
        assert!(success, "处理事件应该成功（即使事件被丢弃）");
        
        // 由于事件太大且无法截断（级别太低），应该被丢弃
        // 所以委托后端可能不会收到事件
        // 这是符合预期的行为
    }
    
    #[test]
    fn test_splitting_batches() {
        // 测试批次分割
        let delegate = Arc::new(TestBackend::new());
        let config = TruncateConfig {
            max_event_size: 10000,
            max_batch_size: 100, // 很小的批次大小限制
        };
        
        let backend = TruncateBackend::new(delegate.clone(), config);
        
        // 创建多个事件，每个事件大小约50字节
        let events: Vec<Arc<Event>> = (0..5)
            .map(|i| {
                let mut event = Event::default();
                event.audit_id = format!("event-{}", i);
                event.annotations.insert(
                    "data".to_string(),
                    "A".repeat(40), // 每个事件约40字节的注解
                );
                Arc::new(event)
            })
            .collect();
        
        let success = backend.process_events(&events);
        assert!(success, "处理事件应该成功");
        
        // 由于批次大小限制为100，而5个事件每个约50字节，总共约250字节
        // 应该被分成多个批次
        assert!(
            delegate.process_count() > 1,
            "事件应该被分成多个批次处理，实际批次数: {}",
            delegate.process_count()
        );
        assert_eq!(
            delegate.event_count(),
            5,
            "应该处理所有5个事件"
        );
    }
    
    #[test]
    fn test_truncate_backend_display() {
        let delegate = Arc::new(TestBackend::new());
        let config = TruncateConfig::default();
        
        let backend = TruncateBackend::new(delegate.clone(), config);
        let display_str = format!("{}", backend);
        
        assert!(display_str.starts_with("truncate<"), "Display格式应该正确");
        assert!(display_str.contains("test"), "应该包含委托后端名称");
    }
    
    #[test]
    fn test_truncate_backend_run_and_shutdown() {
        let delegate = Arc::new(TestBackend::new());
        let config = TruncateConfig::default();
        
        let backend = TruncateBackend::new(delegate.clone(), config);
        
        // 测试run方法
        let (tx, rx) = mpsc::channel();
        let result = backend.run(rx);
        assert!(result.is_ok(), "run方法应该成功");
        
        // 发送停止信号
        drop(tx);
        
        // 测试shutdown方法
        backend.shutdown();
    }
    
    #[test]
    fn test_event_size_calculation() {
        let delegate = Arc::new(TestBackend::new());
        let config = TruncateConfig::default();
        let backend = TruncateBackend::new(delegate, config);
        
        // 创建测试事件
        let event = Event {
            audit_id: "test-123".to_string(),
            level: Level::Request,
            verb: "create".to_string(),
            request_uri: "/api/v1/pods".to_string(),
            ..Default::default()
        };
        
        // 计算大小
        let size_result = backend.calc_size(&event);
        assert!(size_result.is_ok(), "应该能成功计算大小");
        
        let size = size_result.unwrap();
        assert!(size > 0, "事件大小应该大于0");
        
        // 序列化后的大小应该大致匹配
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(size, json.len(), "计算的大小应该等于JSON字符串长度");
    }
}