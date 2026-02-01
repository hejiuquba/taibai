/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//! 联合后端
//!
//! 此模块实现了审计后端联合，可以将多个后端组合成一个后端。

use k8s_audit_apis::audit as audit_internal;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;

use crate::types::{Backend, BackendError, Sink};

/// 创建联合后端，将事件记录到一组后端中。
/// 返回的 Sink 实现会依次阻塞调用每个后端的 ProcessEvents。
///
/// # 参数
/// * `backends` - 要组合的后端向量
///
/// # 返回值
/// * `Arc<dyn Backend>` - 组合后的后端
///
/// # 注意
/// 如果只有一个后端，直接返回该后端（优化）。
pub fn union_backend(backends: Vec<Arc<dyn Backend>>) -> Arc<dyn Backend> {
    if backends.len() == 1 {
        // 只有一个后端，直接返回
        return backends.into_iter().next().unwrap();
    }

    Arc::new(UnionBackend {
        backends: Arc::new(backends),
    })
}

/// 联合后端结构体
struct UnionBackend {
    /// 后端列表
    backends: Arc<Vec<Arc<dyn Backend>>>,
}

impl Backend for UnionBackend {
    fn run(&self, stop_rx: mpsc::Receiver<()>) -> Result<(), BackendError> {
        let backends = self.backends.clone();

        // 使用原子布尔值作为停止标志
        let stop_flag = Arc::new(AtomicBool::new(false));

        // 监听停止信号的线程
        let stop_flag_for_listener = stop_flag.clone();
        let listener_handle = thread::spawn(move || {
            // 等待停止信号
            let _ = stop_rx.recv();
            stop_flag_for_listener.store(true, Ordering::SeqCst);
        });

        // 为每个后端启动线程
        let mut handles = Vec::new();
        for backend in backends.iter() {
            let backend_clone = backend.clone();
            let stop_flag_for_backend = stop_flag.clone();

            let handle = thread::spawn(move || {
                // 为这个后端创建停止信号通道
                let (stop_tx, stop_rx_for_backend) = mpsc::channel();

                // 检查停止标志的线程
                let stop_flag_for_checker = stop_flag_for_backend.clone();
                let stop_tx_for_checker = stop_tx.clone();
                let checker_handle = thread::spawn(move || {
                    // 等待停止标志被设置
                    while !stop_flag_for_checker.load(Ordering::SeqCst) {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    // 发送停止信号给后端
                    let _ = stop_tx_for_checker.send(());
                });

                // 运行后端
                let result = backend_clone.run(stop_rx_for_backend);

                // 等待检查线程结束
                let _ = checker_handle.join();
                result
            });

            handles.push(handle);
        }

        // 等待所有后端线程完成
        let mut errors = Vec::new();
        let mut all_success = true;

        for handle in handles {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    errors.push(err);
                    all_success = false;
                }
                Err(panic) => {
                    let panic_msg = if let Some(msg) = panic.downcast_ref::<&str>() {
                        format!("后端线程panic: {}", msg)
                    } else if let Some(msg) = panic.downcast_ref::<String>() {
                        format!("后端线程panic: {}", msg)
                    } else {
                        "后端线程panic: 未知原因".to_string()
                    };
                    errors.push(BackendError::new(panic_msg));
                    all_success = false;
                }
            }
        }

        // 等待监听线程结束
        let _ = listener_handle.join();

        if !all_success {
            let error_messages: Vec<String> =
                errors.into_iter().map(|err| err.to_string()).collect();
            return Err(BackendError::new(format!(
                "联合后端运行失败: {}",
                error_messages.join("; ")
            )));
        }

        Ok(())
    }

    fn shutdown(&self) {
        for backend in self.backends.iter() {
            backend.shutdown();
        }
    }

    fn name(&self) -> &str {
        "union"
    }

    fn is_healthy(&self) -> bool {
        // 联合后端的健康状态：所有后端都健康才算健康
        self.backends.iter().all(|backend| backend.is_healthy())
    }
}

impl Sink for UnionBackend {
    fn process_events(&self, events: &[Arc<audit_internal::Event>]) -> bool {
        let mut success = true;

        for backend in self.backends.iter() {
            // 依次调用每个后端的 process_events
            // 全部成功才返回 true
            success = backend.process_events(events) && success;
        }

        success
    }
}

impl fmt::Display for UnionBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let backend_names: Vec<String> = self
            .backends
            .iter()
            .map(|backend| backend.name().to_string())
            .collect();

        write!(f, "union[{}]", backend_names.join(","))
    }
}

impl fmt::Debug for UnionBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnionBackend {{ backends: {} }}", self)
    }
}

/// 简单的测试后端实现
#[cfg(test)]
pub(crate) struct MockBackend {
    name: String,
    should_succeed: AtomicBool,
    events_processed: std::sync::Mutex<Vec<Arc<audit_internal::Event>>>,
    shutdown_called: AtomicBool,
}

#[cfg(test)]
impl MockBackend {
    pub(crate) fn new(name: &str, should_succeed: bool) -> Self {
        Self {
            name: name.to_string(),
            should_succeed: AtomicBool::new(should_succeed),
            events_processed: std::sync::Mutex::new(Vec::new()),
            shutdown_called: AtomicBool::new(false),
        }
    }

    pub(crate) fn events_count(&self) -> usize {
        self.events_processed.lock().unwrap().len()
    }

    pub(crate) fn set_should_succeed(&self, succeed: bool) {
        self.should_succeed.store(succeed, Ordering::SeqCst);
    }

    pub(crate) fn was_shutdown_called(&self) -> bool {
        self.shutdown_called.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
impl Backend for MockBackend {
    fn run(&self, _stop_rx: mpsc::Receiver<()>) -> Result<(), BackendError> {
        // 模拟后端运行
        Ok(())
    }

    fn shutdown(&self) {
        self.shutdown_called.store(true, Ordering::SeqCst);
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn is_healthy(&self) -> bool {
        true
    }
}

#[cfg(test)]
impl Sink for MockBackend {
    fn process_events(&self, events: &[Arc<audit_internal::Event>]) -> bool {
        let mut events_guard = self.events_processed.lock().unwrap();
        events_guard.extend(events.iter().cloned());

        self.should_succeed.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn create_test_event() -> Arc<audit_internal::Event> {
        Arc::new(audit_internal::Event {
            audit_id: "test-audit-id".to_string(),
            level: audit_internal::Level::Metadata,
            stage: audit_internal::Stage::RequestReceived,
            request_uri: "/api/v1/pods".to_string(),
            ..Default::default()
        })
    }

    #[test]
    fn test_union_backend_single_backend() {
        // 测试只有一个后端的情况（优化路径）
        let backend1 = Arc::new(MockBackend::new("backend1", true));
        let backends = vec![backend1.clone() as Arc<dyn Backend>];

        let union = union_backend(backends);

        // 应该直接返回原后端，而不是包装器
        assert_eq!(union.name(), "backend1");
    }

    #[test]
    fn test_union_backend_multiple_backends() {
        // 测试多个后端
        let backend1 = Arc::new(MockBackend::new("backend1", true));
        let backend2 = Arc::new(MockBackend::new("backend2", true));
        let backends: Vec<Arc<dyn Backend>> = vec![
            backend1.clone() as Arc<dyn Backend>,
            backend2.clone() as Arc<dyn Backend>,
        ];

        let union = union_backend(backends);

        assert_eq!(union.name(), "union");
        assert!(union.is_healthy());
    }

    #[test]
    fn test_union_process_events_all_succeed() {
        // 测试所有后端都成功处理事件
        let backend1 = Arc::new(MockBackend::new("backend1", true));
        let backend2 = Arc::new(MockBackend::new("backend2", true));
        let backends: Vec<Arc<dyn Backend>> = vec![
            backend1.clone() as Arc<dyn Backend>,
            backend2.clone() as Arc<dyn Backend>,
        ];

        let union = union_backend(backends);

        let event = create_test_event();
        let success = union.process_events(&[event.clone()]);

        assert!(success);
        assert_eq!(backend1.events_count(), 1);
        assert_eq!(backend2.events_count(), 1);
    }

    #[test]
    fn test_union_process_events_one_fails() {
        // 测试有一个后端失败
        let backend1 = Arc::new(MockBackend::new("backend1", true));
        let backend2 = Arc::new(MockBackend::new("backend2", false)); // 这个会失败
        let backends: Vec<Arc<dyn Backend>> = vec![
            backend1.clone() as Arc<dyn Backend>,
            backend2.clone() as Arc<dyn Backend>,
        ];

        let union = union_backend(backends);

        let event = create_test_event();
        let success = union.process_events(&[event.clone()]);

        // 有一个失败，整体应该返回 false
        assert!(!success);
        assert_eq!(backend1.events_count(), 1);
        assert_eq!(backend2.events_count(), 1);
    }

    #[test]
    fn test_union_process_events_all_fail() {
        // 测试所有后端都失败
        let backend1 = Arc::new(MockBackend::new("backend1", false));
        let backend2 = Arc::new(MockBackend::new("backend2", false));
        let backends: Vec<Arc<dyn Backend>> = vec![
            backend1.clone() as Arc<dyn Backend>,
            backend2.clone() as Arc<dyn Backend>,
        ];

        let union = union_backend(backends);

        let event = create_test_event();
        let success = union.process_events(&[event.clone()]);

        assert!(!success);
        assert_eq!(backend1.events_count(), 1);
        assert_eq!(backend2.events_count(), 1);
    }

    #[test]
    fn test_union_process_events_multiple_events() {
        // 测试处理多个事件
        let backend1 = Arc::new(MockBackend::new("backend1", true));
        let backend2 = Arc::new(MockBackend::new("backend2", true));
        let backends: Vec<Arc<dyn Backend>> = vec![
            backend1.clone() as Arc<dyn Backend>,
            backend2.clone() as Arc<dyn Backend>,
        ];

        let union = union_backend(backends);

        let event1 = create_test_event();
        let event2 = Arc::new(audit_internal::Event {
            audit_id: "test-audit-id-2".to_string(),
            ..Default::default()
        });

        let success = union.process_events(&[event1.clone(), event2.clone()]);

        assert!(success);
        assert_eq!(backend1.events_count(), 2);
        assert_eq!(backend2.events_count(), 2);
    }

    #[test]
    fn test_union_shutdown() {
        // 测试关闭功能
        let backend1 = Arc::new(MockBackend::new("backend1", true));
        let backend2 = Arc::new(MockBackend::new("backend2", true));
        let backends: Vec<Arc<dyn Backend>> = vec![
            backend1.clone() as Arc<dyn Backend>,
            backend2.clone() as Arc<dyn Backend>,
        ];

        let union = union_backend(backends);

        // 初始状态：未关闭
        assert!(!backend1.was_shutdown_called());
        assert!(!backend2.was_shutdown_called());

        // 执行关闭
        union.shutdown();

        // 应该所有后端都被关闭
        assert!(backend1.was_shutdown_called());
        assert!(backend2.was_shutdown_called());
    }

    #[test]
    fn test_union_run_success() {
        // 测试运行成功
        let backend1 = Arc::new(MockBackend::new("backend1", true));
        let backend2 = Arc::new(MockBackend::new("backend2", true));
        let backends: Vec<Arc<dyn Backend>> = vec![
            backend1.clone() as Arc<dyn Backend>,
            backend2.clone() as Arc<dyn Backend>,
        ];

        let union = union_backend(backends);

        let (stop_tx, stop_rx) = mpsc::channel();

        // 启动联合后端
        let union_clone = union.clone();
        let run_handle = thread::spawn(move || union_clone.run(stop_rx));

        // 等待一小段时间确保后端启动
        thread::sleep(std::time::Duration::from_millis(50));

        // 发送停止信号
        stop_tx.send(()).unwrap();

        // 等待运行结束
        let result = run_handle.join().unwrap();

        assert!(result.is_ok());
    }

    #[test]
    fn test_union_run_with_backend_error() {
        // 创建一个会失败的后端
        struct FailingBackend;

        impl Backend for FailingBackend {
            fn run(&self, _stop_rx: mpsc::Receiver<()>) -> Result<(), BackendError> {
                // 模拟后端运行失败
                Err(BackendError::new("模拟后端运行失败"))
            }

            fn shutdown(&self) {}

            fn name(&self) -> &str {
                "failing-backend"
            }

            fn is_healthy(&self) -> bool {
                false
            }
        }

        impl Sink for FailingBackend {
            fn process_events(&self, _events: &[Arc<audit_internal::Event>]) -> bool {
                true
            }
        }

        let backend1 = Arc::new(MockBackend::new("backend1", true));
        let backend2 = Arc::new(FailingBackend);
        let backends: Vec<Arc<dyn Backend>> = vec![
            backend1.clone() as Arc<dyn Backend>,
            backend2.clone() as Arc<dyn Backend>,
        ];

        let union = union_backend(backends);

        let (_stop_tx, stop_rx) = mpsc::channel();

        // 运行应该失败
        let result = union.run(stop_rx);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("联合后端运行失败"));
        assert!(err_msg.contains("模拟后端运行失败"));
    }

    #[test]
    fn test_union_display() {
        // 测试 Display 实现
        let backend1 = Arc::new(MockBackend::new("backend1", true));
        let backend2 = Arc::new(MockBackend::new("backend2", true));
        let backends: Vec<Arc<dyn Backend>> = vec![
            backend1.clone() as Arc<dyn Backend>,
            backend2.clone() as Arc<dyn Backend>,
        ];

        let union = union_backend(backends);

        let display_str = format!("{}", union.name());
        assert_eq!(display_str, "union[backend1,backend2]");
    }

    #[test]
    fn test_union_is_healthy() {
        // 测试健康检查
        let backend1 = Arc::new(MockBackend::new("backend1", true));
        let backend2 = Arc::new(MockBackend::new("backend2", true));
        let backends: Vec<Arc<dyn Backend>> = vec![
            backend1.clone() as Arc<dyn Backend>,
            backend2.clone() as Arc<dyn Backend>,
        ];

        let union = union_backend(backends.clone());

        // 所有后端都健康，联合后端应该健康
        assert!(union.is_healthy());

        // 创建一个不健康的后端
        struct UnhealthyBackend;

        impl Backend for UnhealthyBackend {
            fn run(&self, _stop_rx: mpsc::Receiver<()>) -> Result<(), BackendError> {
                Ok(())
            }

            fn shutdown(&self) {}

            fn name(&self) -> &str {
                "unhealthy-backend"
            }

            fn is_healthy(&self) -> bool {
                false
            }
        }

        impl Sink for UnhealthyBackend {
            fn process_events(&self, _events: &[Arc<audit_internal::Event>]) -> bool {
                true
            }
        }

        let backend3 = Arc::new(UnhealthyBackend);
        let backends_with_unhealthy: Vec<Arc<dyn Backend>> = vec![
            backend1.clone() as Arc<dyn Backend>,
            backend3.clone() as Arc<dyn Backend>,
        ];
        let union_with_unhealthy = union_backend(backends_with_unhealthy);

        // 有一个后端不健康，联合后端应该不健康
        assert!(!union_with_unhealthy.is_healthy());
    }

    #[test]
    fn test_union_empty_backends() {
        // 测试空后端列表（边界情况）
        let backends: Vec<Arc<dyn Backend>> = Vec::new();
        let union = union_backend(backends);

        // 空列表应该创建空联合后端
        assert_eq!(union.name(), "union");

        // 处理事件应该成功（因为没有后端需要处理）
        let event = create_test_event();
        let success = union.process_events(&[event.clone()]);
        assert!(success);

        // 运行应该成功
        let (_stop_tx, stop_rx) = mpsc::channel();
        let result = union.run(stop_rx);
        assert!(result.is_ok());

        // 关闭应该无错误
        union.shutdown();
    }
}
