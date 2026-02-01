// k8s-audit-plugins/src/log/mod.rs

//! 日志后端插件
//!
//! 这个模块提供了基于标准输出和文件的审计日志后端。
//!
//! 支持的格式：
//! - legacy: 单行文本格式
//! - json: 结构化JSON格式

use std::fmt;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::sync::mpsc;

use k8s_audit_apis::audit as audit_internal;
use k8s_audit_core::types::{Backend, BackendError, Sink};

/// 支持的日志格式常量
pub const FORMAT_LEGACY: &str = "legacy";
pub const FORMAT_JSON: &str = "json";

/// 插件名称
pub const PLUGIN_NAME: &str = "log";

/// 允许的格式列表
pub static ALLOWED_FORMATS: &[&str] = &[FORMAT_LEGACY, FORMAT_JSON];

/// 处理插件错误的辅助函数（对应Go的audit.HandlePluginError）
///
/// 在Rust中，我们只是简单地将错误打印到标准错误输出
fn handle_plugin_error(plugin_name: &str, err: impl fmt::Display, event: &audit_internal::Event) {
    eprintln!("插件'{}'处理事件时出错: {} - 事件ID: {}", plugin_name, err, event.audit_id);
}

/// 将事件格式化为单行文本的辅助函数（对应Go的audit.EventString）
///
/// 注意：这是一个简化的实现，Go的EventString有更复杂的格式
fn event_string(event: &audit_internal::Event) -> String {
    // 这里是一个简化的实现，实际应该匹配Go的EventString格式
    // 我们使用基本的字段格式化
    let stage = event.stage.as_str();
    
    let ip = if !event.source_ips.is_empty() {
        event.source_ips.first().unwrap()
    } else {
        "<unknown>"
    };
    
    let user = if !event.user.username.as_deref().unwrap_or("<none>").is_empty() {
        &event.user.username
    } else {
        &Some("<none>".to_string())
    };
    
    // 格式化组信息
    let groups = match &event.user.groups {
        Some(user_groups) if !user_groups.is_empty() => {
            let quoted_groups: Vec<String> = user_groups
                .iter()
                .map(|g| format!("\"{}\"", g))
                .collect();
            quoted_groups.join(",")
        }
        _ => "<none>".to_string(),
    };
    
    let namespace = event.object_ref
        .as_ref()
        .and_then(|r| r.namespace.as_deref())
        .unwrap_or("<none>");
    
    let response = event.response_status
        .as_ref()
        .and_then(|s| s.code)
        .map(|code| code.to_string())
        .unwrap_or_else(|| "<deferred>".to_string());
    
    let user_agent = event.user_agent.as_deref().unwrap_or("");
    
    format!(
        "AUDIT: id=\"{}\" stage=\"{}\" ip=\"{}\" method=\"{}\" user=\"{}\" groups=\"{}\" as=\"<self>\" asgroups=\"<lookup>\" user-agent=\"{}\" namespace=\"{}\" uri=\"{}\" response=\"{}\"",
        event.audit_id,
        stage,
        ip,
        event.verb,
        user.as_deref().unwrap_or("<none>"),
        groups,
        user_agent,
        namespace,
        event.request_uri,
        response
    )
}

/// 日志后端结构体
///
/// 这个结构体实现了审计日志后端，支持将事件写入到任何实现了`Write` trait的输出流。
pub struct LogBackend<W: Write + Send + Sync + 'static> {
    /// 输出流（使用Mutex包装以确保线程安全）
    out: Arc<Mutex<W>>,
    /// 输出格式
    format: String,
}

impl<W: Write + Send + Sync + 'static> LogBackend<W> {
    /// 创建新的日志后端
    ///
    /// # 参数
    /// - `out`: 输出流，实现了`Write` trait
    /// - `format`: 输出格式，必须是`FORMAT_LEGACY`或`FORMAT_JSON`
    ///
    /// # 注意
    /// 与Go版本不同，Rust版本不需要groupVersion参数，
    /// 因为我们使用serde_json进行JSON序列化，它会自动处理版本
    pub fn new(out: W, format: &str) -> Self {
        Self {
            out: Arc::new(Mutex::new(out)),
            format: format.to_string(),
        }
    }
}

impl<W: Write + Send + Sync + 'static> Sink for LogBackend<W> {
    fn process_events(&self, events: &[Arc<audit_internal::Event>]) -> bool {
        let mut success = true;
        
        // 锁定输出流
        let mut out_guard = match self.out.lock() {
            Ok(guard) => guard,
            Err(_) => return false, // 如果无法获取锁，返回失败
        };
        
        for event in events {
            let line = match self.format.as_str() {
                FORMAT_LEGACY => {
                    // 使用简化的事件字符串格式化
                    format!("{}\n", event_string(event))
                }
                FORMAT_JSON => {
                    // 使用serde_json进行JSON序列化
                    match serde_json::to_string(&**event) {
                        Ok(json) => json,
                        Err(err) => {
                            handle_plugin_error(PLUGIN_NAME, err, event);
                            success = false;
                            continue;
                        }
                    }
                }
                _ => {
                    // 处理未知格式
                    let err_msg = format!(
                        "日志格式 '{}' 不在已知格式列表中 ({})",
                        self.format,
                        ALLOWED_FORMATS.join(", ")
                    );
                    handle_plugin_error(PLUGIN_NAME, &err_msg, event);
                    success = false;
                    continue;
                }
            };
            
            // 写入输出流
            if let Err(err) = out_guard.write_all(line.as_bytes()) {
                handle_plugin_error(PLUGIN_NAME, err, event);
                success = false;
            }
        }
        
        success
    }
}

impl<W: Write + Send + Sync + 'static> Backend for LogBackend<W> {
    fn run(&self, stop_rx: mpsc::Receiver<()>) -> Result<(), BackendError> {
        // 日志后端不需要后台运行，但我们监听停止信号
        // 以防万一需要清理资源
        std::thread::spawn(move || {
            // 等待停止信号
            let _ = stop_rx.recv();
            // 收到信号后可以执行清理操作
        });
        
        Ok(())
    }
    
    fn shutdown(&self) {
        // 日志后端不需要特殊的关闭操作
        // 如果有缓冲数据需要刷新，可以在这里处理
    }
    
    fn name(&self) -> &str {
        PLUGIN_NAME
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_audit_apis::audit::{Event, Level, ObjectReference, Stage, UserInfo};
    use k8s_audit_apis::audit::Status;
    use std::io::Cursor;
    use regex::Regex;
    use uuid::Uuid;
    
    fn create_test_event() -> Event {
        Event {
            audit_id: Uuid::new_v4().to_string(),
            stage: Stage::RequestReceived,
            verb: "get".to_string(),
            request_uri: "/apis/rbac.authorization.k8s.io/v1/roles".to_string(),
            user: UserInfo {
                username: Some("admin".to_string()),
                groups: vec![
                    "system:masters".to_string(),
                    "system:authenticated".to_string(),
                ].into(),
                ..Default::default()
            },
            source_ips: vec!["127.0.0.1".to_string()],
            user_agent: Some("kube-admin".to_string()),
            object_ref: Some(ObjectReference {
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }
    
    #[test]
    fn test_log_events_legacy() {
        let test_cases = vec![
            (
                Event {
                    audit_id: "test-id-1".to_string(),
                    ..Default::default()
                },
                r#"AUDIT: id="test-id-1" stage="" ip="<unknown>" method="" user="<none>" groups="<none>" as="<self>" asgroups="<lookup>" user-agent="" namespace="<none>" uri="" response="<deferred>"#,
            ),
            (
                Event {
                    response_status: Some(Status {
                        code: Some(200),
                        ..Default::default()
                    }),
                    request_uri: "/apis/rbac.authorization.k8s.io/v1/roles".to_string(),
                    source_ips: vec!["127.0.0.1".to_string()],
                    audit_id: Uuid::new_v4().to_string(),
                    stage: Stage::RequestReceived,
                    verb: "get".to_string(),
                    user: UserInfo {
                        username: Some("admin".to_string()),
                        groups: vec![
                            "system:masters".to_string(),
                            "system:authenticated".to_string(),
                        ].into(),
                        ..Default::default()
                    },
                    user_agent: Some("kube-admin".to_string()),
                    object_ref: Some(ObjectReference {
                        namespace: Some("default".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                // 注意：组格式应该是 "\"system:masters\",\"system:authenticated\""
                r#"AUDIT: id="[\w-]+" stage="RequestReceived" ip="127.0.0.1" method="get" user="admin" groups=""system:masters","system:authenticated"" as="<self>" asgroups="<lookup>" user-agent="kube-admin" namespace="default" uri="/apis/rbac.authorization.k8s.io/v1/roles" response="200""#,
            ),
            (
                Event {
                    audit_id: Uuid::new_v4().to_string(),
                    level: Level::Metadata,
                    object_ref: Some(ObjectReference {
                        resource: Some("foo".to_string()),
                        api_version: Some("v1".to_string()),
                        subresource: Some("bar".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                r#"AUDIT: id="[\w-]+" stage="" ip="<unknown>" method="" user="<none>" groups="<none>" as="<self>" asgroups="<lookup>" user-agent="" namespace="<none>" uri="" response="<deferred>"#,
            ),
        ];
        
        for (event, expected_pattern) in test_cases {
            let buffer = Cursor::new(Vec::new());
            let backend = LogBackend::new(buffer, FORMAT_LEGACY);
            
            let event_arc = Arc::new(event);
            let success = backend.process_events(&[event_arc]);
            assert!(success, "处理事件应该成功");
            
            // 获取输出
            let backend_inner = backend.out.lock().unwrap();
            let output = String::from_utf8(backend_inner.get_ref().clone()).unwrap();
            
            // 使用正则表达式验证输出格式
            let re = Regex::new(expected_pattern).unwrap();
            assert!(
                re.is_match(output.trim()),
                "输出不匹配模式:\n期望: {}\n实际: {}",
                expected_pattern,
                output.trim()
            );
        }
    }
    
    #[test]
    fn test_log_events_json() {
        let test_events = vec![
            Event {
                audit_id: "test-id-2".to_string(),
                ..Default::default()
            },
            create_test_event(),
            Event {
                audit_id: "test-id-3".to_string(),
                level: Level::Metadata,
                object_ref: Some(ObjectReference {
                    resource: Some("foo".to_string()),
                    api_version: Some("v1".to_string()),
                    subresource: Some("bar".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ];
        
        for event in test_events {
            let buffer = Cursor::new(Vec::new());
            let backend = LogBackend::new(buffer, FORMAT_JSON);
            
            let event_arc = Arc::new(event.clone());
            let success = backend.process_events(&[event_arc]);
            assert!(success, "处理事件应该成功");
            
            // 获取输出
            let backend_inner = backend.out.lock().unwrap();
            let output = String::from_utf8(backend_inner.get_ref().clone()).unwrap();
            
            // 验证JSON可以被正确解析
            let parsed: Result<Event, _> = serde_json::from_str(&output);
            assert!(
                parsed.is_ok(),
                "JSON输出应该可以被正确解析: {}",
                output
            );
            
            // 注意：由于序列化/反序列化可能丢失一些信息（如时间戳精度），
            // 我们不进行深度相等比较，只验证基本结构
            let parsed_event = parsed.unwrap();
            assert_eq!(parsed_event.audit_id, event.audit_id);
        }
    }
    
    #[test]
    fn test_invalid_format() {
        let buffer = Cursor::new(Vec::new());
        let backend = LogBackend::new(buffer, "invalid-format");
        
        let event = Event {
            audit_id: "test-id".to_string(),
            ..Default::default()
        };
        
        let event_arc = Arc::new(event);
        let success = backend.process_events(&[event_arc]);
        
        // 使用无效格式应该失败
        assert!(!success, "使用无效格式应该返回失败");
    }
    
    #[test]
    fn test_backend_name() {
        let buffer = Cursor::new(Vec::new());
        let backend = LogBackend::new(buffer, FORMAT_JSON);
        
        assert_eq!(backend.name(), PLUGIN_NAME);
    }
    
    #[test]
    fn test_backend_run_and_shutdown() {
        let buffer = Cursor::new(Vec::new());
        let backend = LogBackend::new(buffer, FORMAT_JSON);
        
        // 测试run方法
        let (tx, rx) = mpsc::channel();
        let result = backend.run(rx);
        assert!(result.is_ok(), "run方法应该成功");
        
        // 发送停止信号
        tx.send(()).unwrap();
        
        // 测试shutdown方法
        backend.shutdown();
    }
}