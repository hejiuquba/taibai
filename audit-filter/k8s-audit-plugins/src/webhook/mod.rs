// k8s-audit-plugins/src/webhook/mod.rs

//! Webhook后端插件
//!
//! 这个模块实现了通过HTTP webhooks发送审计事件的后端。
//! 它支持重试机制、指数退避和配置加载。

use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use std::time::Duration;

use reqwest::{Client, ClientBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json;
use tokio::runtime::{Handle, Runtime};
use url::Url;

use k8s_audit_apis::audit as audit_internal;
use k8s_audit_core::types::{Backend, BackendError, Sink};
// 在文件顶部添加导入
use futures_util::TryFutureExt;

/// 插件名称
pub const PLUGIN_NAME: &str = "webhook";

/// 默认的初始退避延迟
pub const DEFAULT_INITIAL_BACKOFF_DELAY: Duration = Duration::from_secs(10);

/// Webhook配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook服务器URL
    pub url: String,
    /// 是否跳过TLS验证（仅用于测试）
    #[serde(default)]
    pub insecure_skip_tls_verify: bool,
    /// 超时时间（秒）
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
}

fn default_timeout_seconds() -> u64 {
    30
}

/// 重试配置
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// 初始退避延迟
    pub initial_delay: Duration,
    /// 退避乘数因子
    pub multiplier: f64,
    /// 随机抖动因子（0.0到1.0）
    pub jitter_factor: f64,
    /// 最大重试次数
    pub max_retries: usize,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            initial_delay: DEFAULT_INITIAL_BACKOFF_DELAY,
            multiplier: 1.5,
            jitter_factor: 0.2,
            max_retries: 5,
        }
    }
}

/// Webhook后端
pub struct WebhookBackend {
    /// HTTP客户端
    client: Arc<Client>,
    /// Webhook URL
    url: Url,
    /// 重试配置
    retry_config: RetryConfig,
    /// 后端名称
    name: String,
    /// 异步运行时句柄
    #[allow(dead_code)]
    runtime: Option<Arc<Runtime>>,
    /// 请求计数器（用于测试和监控）
    request_count: Arc<Mutex<usize>>,
}

impl WebhookBackend {
    /// 从配置创建新的Webhook后端
    pub fn new(config: WebhookConfig, retry_config: Option<RetryConfig>) -> Result<Self, BackendError> {
        // 解析URL
        let url = Url::parse(&config.url)
            .map_err(|e| BackendError::new(format!("无效的webhook URL: {}", e)))?;
        
        // 创建HTTP客户端
        let mut client_builder = ClientBuilder::new();
        
        // 设置超时
        client_builder = client_builder.timeout(Duration::from_secs(config.timeout_seconds));
        
        // 如果跳过TLS验证（仅用于测试）
        if config.insecure_skip_tls_verify {
            #[cfg(feature = "dangerous-config")]
            {
                use reqwest::Certificate;
                // 注意：这仅用于测试环境
                client_builder = client_builder.danger_accept_invalid_certs(true);
            }
        }
        
        let client = client_builder
            .build()
            .map_err(|e| BackendError::new(format!("创建HTTP客户端失败: {}", e)))?;
        
        // 创建异步运行时
        let runtime = Runtime::new()
            .map_err(|e| BackendError::new(format!("创建异步运行时失败: {}", e)))?;
        
        Ok(Self {
            client: Arc::new(client),
            url,
            retry_config: retry_config.unwrap_or_default(),
            name: PLUGIN_NAME.to_string(),
            runtime: Some(Arc::new(runtime)),
            request_count: Arc::new(Mutex::new(0)),
        })
    }
    
    /// 从kubeconfig文件创建Webhook后端（简化版本）
    pub fn from_kubeconfig(
        kubeconfig_path: impl AsRef<Path>,
        retry_config: Option<RetryConfig>,
    ) -> Result<Self, BackendError> {
        // 简化实现：读取配置文件
        let config_str = std::fs::read_to_string(kubeconfig_path)
            .map_err(|e| BackendError::new(format!("读取kubeconfig文件失败: {}", e)))?;
        
        // 解析kubeconfig（简化版本，实际应该支持完整的kubeconfig格式）
        #[derive(Deserialize)]
        struct KubeConfig {
            clusters: Option<Vec<ClusterEntry>>,
        }
        
        #[derive(Deserialize)]
        struct ClusterEntry {
            cluster: Option<Cluster>,
        }
        
        #[derive(Deserialize)]
        struct Cluster {
            server: Option<String>,
            insecure_skip_tls_verify: Option<bool>,
        }
        
        let kubeconfig: KubeConfig = serde_yaml::from_str(&config_str)
            .map_err(|e| BackendError::new(format!("解析kubeconfig失败: {}", e)))?;
        
        // 获取第一个集群配置
        let cluster = kubeconfig.clusters
            .and_then(|clusters| clusters.into_iter().next())
            .and_then(|entry| entry.cluster)
            .ok_or_else(|| BackendError::new("kubeconfig中没有找到集群配置"))?;
        
        let server_url = cluster.server
            .ok_or_else(|| BackendError::new("集群配置中没有server字段"))?;
        
        // 创建Webhook配置
        let webhook_config = WebhookConfig {
            url: server_url,
            insecure_skip_tls_verify: cluster.insecure_skip_tls_verify.unwrap_or(false),
            timeout_seconds: 30,
        };
        
        Self::new(webhook_config, retry_config)
    }
    
    /// 创建动态后端（用于测试）
    pub fn new_dynamic(
        url: Url,
        client: Client,
        retry_config: RetryConfig,
    ) -> Self {
        Self {
            client: Arc::new(client),
            url,
            retry_config,
            name: format!("dynamic_{}", PLUGIN_NAME),
            runtime: None,
            request_count: Arc::new(Mutex::new(0)),
        }
    }
    
    /// 发送事件到webhook（带重试）
    fn send_events_with_retry(&self, events: &[Arc<audit_internal::Event>]) -> Result<(), String> {
        // 递增请求计数
        {
            let mut count = self.request_count.lock().unwrap();
            *count += 1;
        }
        
        // 准备请求体
        let event_list = audit_internal::EventList {
            items: events.iter().map(|e| (**e).clone()).collect(),
            ..Default::default()
        };
        
        let body = match serde_json::to_string(&event_list) {
            Ok(json) => json,
            Err(e) => return Err(format!("序列化事件失败: {}", e)),
        };
        
        // 指数退避重试
        let mut delay = self.retry_config.initial_delay;
        let mut last_error = None;
        
        for attempt in 0..=self.retry_config.max_retries {
            // 如果是重试，等待一段时间
            if attempt > 0 {
                // 添加抖动
                let jitter = if self.retry_config.jitter_factor > 0.0 {
                    let rand_jitter = rand::random::<f64>() * self.retry_config.jitter_factor;
                    delay.mul_f64(1.0 + rand_jitter)
                } else {
                    delay
                };
                
                std::thread::sleep(jitter);
                
                // 增加延迟
                delay = delay.mul_f64(self.retry_config.multiplier);
            }
            
            // 发送请求
            match self.send_request(&body) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    last_error = Some(e);
                    // 检查是否应该继续重试
                    if attempt == self.retry_config.max_retries {
                        break;
                    }
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| "未知错误".to_string()))
    }
    
    /// 发送单个HTTP请求
    fn send_request(&self, body: &str) -> Result<(), String> {
        // 使用同步请求（简化实现）
        // 在实际生产环境中，应该使用异步请求
        // let response = self.client
        //     .post(self.url.clone())
        //     .header("Content-Type", "application/json")
        //     .body(body.to_string())
        //     .send()
        //     .map_err(|e| format!("发送请求失败: {}", e))?;
        
        // if response.status().is_success() {
        //     Ok(())
        // } else {
        //     Err(format!("Webhook返回错误状态码: {}", response.status()))
        // }

        // 创建运行时
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| format!("创建运行时失败: {}", e))?;
        
        // 在运行时中执行异步代码
        rt.block_on(async {
            let response = self.client
                .post(self.url.clone())
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .send()
                .await
                .map_err(|e| format!("发送请求失败: {}", e))?;
            
            if response.status().is_success() {
                Ok(())
            } else {
                Err(format!("Webhook返回错误状态码: {}", response.status()))
            }
        })
    }
    
    /// 获取请求计数（用于测试）
    pub fn request_count(&self) -> usize {
        *self.request_count.lock().unwrap()
    }
}

impl Sink for WebhookBackend {
    fn process_events(&self, events: &[Arc<audit_internal::Event>]) -> bool {
        match self.send_events_with_retry(events) {
            Ok(_) => true,
            Err(err) => {
                // 处理插件错误
                eprintln!("Webhook插件错误: {}", err);
                false
            }
        }
    }
}

impl Backend for WebhookBackend {
    fn run(&self, stop_rx: mpsc::Receiver<()>) -> Result<(), BackendError> {
        // Webhook后端不需要后台运行，但我们可以监听停止信号
        std::thread::spawn(move || {
            let _ = stop_rx.recv();
            // 收到停止信号，可以执行清理操作
        });
        
        Ok(())
    }
    
    fn shutdown(&self) {
        // 如果有需要清理的资源，可以在这里处理
        if let Some(runtime) = &self.runtime {
            // 关闭异步运行时
            // 注意：这里简化处理，实际可能需要更优雅的关闭
        }
    }
    
    fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for WebhookBackend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_audit_apis::audit::{Event, Stage};
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::NamedTempFile;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    
    fn create_test_event() -> Event {
        Event {
            audit_id: "test-webhook-event".to_string(),
            stage: Stage::RequestReceived,
            verb: "create".to_string(),
            request_uri: "/api/v1/pods".to_string(),
            ..Default::default()
        }
    }
    
    #[tokio::test]
    async fn test_webhook_success() {
        // 启动模拟服务器
        let mock_server = MockServer::start().await;
        
        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_clone = Arc::clone(&request_count);
        
        // 设置模拟响应
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(move |req: &wiremock::Request| {
                request_count_clone.fetch_add(1, Ordering::SeqCst);
                
                // 验证请求体
                let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
                assert!(body.get("items").is_some());
                
                ResponseTemplate::new(200)
            })
            .mount(&mock_server)
            .await;
        
        // 创建Webhook后端
        let webhook_config = WebhookConfig {
            url: mock_server.uri(),
            insecure_skip_tls_verify: true,
            timeout_seconds: 5,
        };
        
        let backend = WebhookBackend::new(webhook_config, None).unwrap();
        
        // 发送事件
        let event = Arc::new(create_test_event());
        let success = backend.process_events(&[event]);
        
        assert!(success, "Webhook请求应该成功");
        assert_eq!(request_count.load(Ordering::SeqCst), 1, "应该发送1个请求");
    }
    
    #[tokio::test]
    async fn test_webhook_retry() {
        // 启动模拟服务器
        let mock_server = MockServer::start().await;
        
        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_clone = Arc::clone(&request_count);
        
        // 设置模拟响应：前两次失败，第三次成功
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(move |req: &wiremock::Request| {
                let count = request_count_clone.fetch_add(1, Ordering::SeqCst);
                
                match count {
                    0 => ResponseTemplate::new(500), // 第一次失败
                    1 => ResponseTemplate::new(503), // 第二次失败
                    _ => ResponseTemplate::new(200), // 后续成功
                }
            })
            .mount(&mock_server)
            .await;
        
        // 创建Webhook后端，使用快速重试配置
        let webhook_config = WebhookConfig {
            url: mock_server.uri(),
            insecure_skip_tls_verify: true,
            timeout_seconds: 5,
        };
        
        let retry_config = RetryConfig {
            initial_delay: Duration::from_millis(50),
            multiplier: 1.5,
            jitter_factor: 0.1,
            max_retries: 3,
        };
        
        let backend = WebhookBackend::new(webhook_config, Some(retry_config)).unwrap();
        
        // 发送事件
        let event = Arc::new(create_test_event());
        let success = backend.process_events(&[event]);
        
        assert!(success, "经过重试后Webhook请求应该成功");
        assert_eq!(request_count.load(Ordering::SeqCst), 3, "应该发送3个请求（2次重试）");
    }
    
    #[test]
    fn test_webhook_from_kubeconfig() {
        // 创建临时kubeconfig文件
        let mut temp_file = NamedTempFile::new().unwrap();
        let kubeconfig_content = r#"
clusters:
- cluster:
    server: https://example.com/audit
    insecure-skip-tls-verify: true
"#;
        
        temp_file.write_all(kubeconfig_content.as_bytes()).unwrap();
        
        // 测试从kubeconfig创建后端
        let result = WebhookBackend::from_kubeconfig(temp_file.path(), None);
        assert!(result.is_ok(), "应该能从有效的kubeconfig创建后端");
        
        let backend = result.unwrap();
        assert_eq!(backend.name(), PLUGIN_NAME);
    }
    
    #[test]
    fn test_invalid_url() {
        // 测试无效URL
        let webhook_config = WebhookConfig {
            url: "not-a-valid-url".to_string(),
            insecure_skip_tls_verify: false,
            timeout_seconds: 5,
        };
        
        let result = WebhookBackend::new(webhook_config, None);
        assert!(result.is_err(), "无效URL应该导致创建失败");
    }
    
    #[test]
    fn test_dynamic_backend() {
        // 测试动态后端创建
        let url = Url::parse("https://example.com/audit").unwrap();
        let client = Client::new();
        let retry_config = RetryConfig::default();
        
        let backend = WebhookBackend::new_dynamic(url, client, retry_config);
        
        assert_eq!(backend.name(), format!("dynamic_{}", PLUGIN_NAME));
    }
    
    #[test]
    fn test_backend_methods() {
        // 创建虚拟配置
        let webhook_config = WebhookConfig {
            url: "https://example.com/audit".to_string(),
            insecure_skip_tls_verify: false,
            timeout_seconds: 5,
        };
        
        let backend = WebhookBackend::new(webhook_config, None).unwrap();
        
        // 测试后端方法
        assert_eq!(backend.name(), PLUGIN_NAME);
        
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