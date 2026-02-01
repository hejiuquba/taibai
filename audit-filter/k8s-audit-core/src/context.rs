/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the above.
*/

//! 审计上下文
//!
//! 此模块定义了审计上下文，用于在请求处理过程中捕获和构造审计事件。

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use k8s_audit_apis::audit as audit_internal;
use k8s_audit_apis::audit::Level;
use k8s_audit_apis::LevelExt;

// ========== 辅助类型 ==========

/// 请求审计配置
#[derive(Debug, Clone)]
pub struct RequestAuditConfig {
    /// 审计级别
    pub level: Level,
    /// 要省略的阶段
    pub omit_stages: Vec<audit_internal::Stage>,
    /// 是否省略托管字段
    pub omit_managed_fields: bool,
}

impl Default for RequestAuditConfig {
    fn default() -> Self {
        Self {
            level: Level::None,
            omit_stages: Vec::new(),
            omit_managed_fields: false,
        }
    }
}

/// 用户信息简化版本
/// 
/// 注意：完整的用户信息在 k8s_audit_apis::audit::UserInfo 中
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    pub uid: String,
    pub groups: Vec<String>,
    pub extra: HashMap<String, Vec<String>>,
}

// ========== 审计上下文核心结构 ==========

/// 审计上下文持有为当前请求构造审计事件的信息
pub struct AuditContext {
    /// 表示是否已初始化，保证对 request_audit_config 和 sink 的安全读取
    /// 应仅通过 init() 方法设置
    initialized: AtomicBool,
    
    /// 适用于请求的审计配置
    /// 应仅通过 init() 写入，仅当 initialized 为 true 时读取
    request_audit_config: Mutex<Option<RequestAuditConfig>>,
    
    /// 处理事件阶段时使用的 sink
    /// 应仅通过 init() 写入，仅当 initialized 为 true 时读取
    sink: Mutex<Option<Arc<dyn crate::Sink>>>,
    
    /// 正在捕获以写入 API 审计日志的审计事件对象
    /// 使用读写锁支持并发读取
    event: RwLock<audit_internal::Event>,
    
    /// 事件中审计ID的未受保护副本
    audit_id: Mutex<Option<String>>,
}

impl AuditContext {
    /// 创建新的审计上下文
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            initialized: AtomicBool::new(false),
            request_audit_config: Mutex::new(None),
            sink: Mutex::new(None),
            event: RwLock::new(audit_internal::Event {
                stage: audit_internal::Stage::ResponseStarted,
                ..Default::default()
            }),
            audit_id: Mutex::new(None),
        })
    }
    
    /// 检查此审计上下文是否启用了审计
    pub fn enabled(&self) -> bool {
        if !self.initialized.load(Ordering::Acquire) {
            // 注意：未设置的 Level 应被视为已启用，以便在评估审计策略之前
            // 仍然可以捕获请求数据（例如注解）
            return true;
        }
        
        if let Some(config) = self.request_audit_config.lock().unwrap().as_ref() {
            config.level != Level::None
        } else {
            true
        }
    }
    
    /// 初始化审计上下文
    /// 
    /// # 参数
    /// * `request_audit_config` - 请求审计配置
    /// * `sink` - 事件处理器
    /// 
    /// # 返回值
    /// 成功时返回 Ok(()), 如果已初始化则返回错误
    pub fn init(
        self: &Arc<Self>,
        request_audit_config: RequestAuditConfig,
        sink: Arc<dyn crate::Sink>,
    ) -> Result<(), ContextError> {
        // 检查是否已初始化
        if self.initialized.load(Ordering::Acquire) {
            return Err(ContextError::AlreadyInitialized);
        }
        
        // 更新配置和 sink（需要互斥访问）
        *self.request_audit_config.lock().unwrap() = Some(request_audit_config.clone());
        *self.sink.lock().unwrap() = Some(sink);
        
        // 更新事件级别（需要写锁）
        let mut event = self.event.write().unwrap();
        event.level = request_audit_config.level;
        
        // 最后设置初始化标志
        self.initialized.store(true, Ordering::Release);
        
        Ok(())
    }
    
    /// 获取审计ID
    pub fn audit_id(&self) -> Option<String> {
        self.audit_id.lock().unwrap().clone()
    }
    
    /// 以只读方式访问事件（对应 Go 的读操作）
    /// 
    /// # 参数
    /// * `f` - 接收事件只读引用的闭包
    /// 
    /// # 返回值
    /// 闭包的返回值
    pub fn with_event_read<F, R>(&self, f: F) -> R
    where
        F: FnOnce(RwLockReadGuard<'_, audit_internal::Event>) -> R,
    {
        let event = self.event.read().unwrap();
        f(event)
    }
    
    /// 以写入方式访问事件（对应 Go 的 visitEvent）
    /// 
    /// # 参数
    /// * `f` - 接收事件可变引用的闭包
    /// 
    /// # 返回值
    /// 闭包的返回值
    pub fn with_event_write<F, R>(&self, f: F) -> R
    where
        F: FnOnce(RwLockWriteGuard<'_, audit_internal::Event>) -> R,
    {
        let event = self.event.write().unwrap();
        f(event)
    }
    
    /// 处理事件阶段
    /// 
    /// # 参数
    /// * `stage` - 要处理的事件阶段
    /// 
    /// # 返回值
    /// 成功时返回 true，处理错误时返回 false
    pub fn process_event_stage(&self, stage: audit_internal::Stage) -> bool {
        if !self.initialized.load(Ordering::Acquire) {
            return true;
        }
        
        let sink_guard = self.sink.lock().unwrap();
        let sink = match sink_guard.as_ref() {
            Some(s) => s,
            None => return true,
        };
        
        let config_guard = self.request_audit_config.lock().unwrap();
        let config = match config_guard.as_ref() {
            Some(c) => c,
            None => return true,
        };
        
        // 检查是否要省略此阶段
        if config.omit_stages.contains(&stage) {
            return true;
        }
        
        // 克隆事件进行处理（需要读锁）
        let event = self.with_event_read(|ev| {
            let mut event_clone = ev.clone();
            event_clone.stage = stage.clone();
            if stage == audit_internal::Stage::RequestReceived {
                event_clone.stage_timestamp = ev.request_received_timestamp.clone();
            } else {
                // 使用当前时间
                event_clone.stage_timestamp = audit_internal::MicroTime::default();
            }
            event_clone
        });
        
        // 使用 Arc 包装事件进行处理
        let event_arc = Arc::new(event);
        
        // 处理事件
        sink.process_events(&[event_arc])
    }
    
    /// 记录被模拟的用户信息
    pub fn log_impersonated_user(&self, user: UserInfo) {
        self.with_event_write(|mut ev| {
            if ev.level.less(&audit_internal::Level::Metadata) {
                return;
            }
            
            // 创建用户信息
            ev.impersonated_user = Some(Box::new(k8s_audit_apis::audit::UserInfo {
                username: Some(user.username),
                uid: Some(user.uid),
                groups: Some(user.groups),
                extra: Some(
                    user.extra
                        .into_iter()
                        .map(|(k, v)| (k, v))
                        .collect(),
                ),
                ..Default::default()
            }));
        });
    }
    
    /// 记录响应对象
    pub fn log_response_object(
        &self,
        status: Option<&audit_internal::Status>,
        obj: Option<&audit_internal::Unknown>,
    ) {
        self.with_event_write(|mut ev| {
            if let Some(status) = status {
                // 选择性复制有界字段
                ev.response_status = Some(audit_internal::Status {
                    status: status.status.clone(),
                    message: status.message.clone(),
                    reason: status.reason.clone(),
                    details: status.details.clone(),
                    code: status.code,
                });
            }
            
            if ev.level.less(&audit_internal::Level::RequestResponse) {
                return;
            }
            
            if let Some(obj) = obj {
                ev.response_object = Some(obj.clone());
            }
        });
    }
    
    /// 记录请求补丁
    pub fn log_request_patch(&self, patch: Vec<u8>) {
        self.with_event_write(|mut ev| {
            ev.request_object = Some(audit_internal::Unknown {
                raw: Some(patch.into()),
                content_type: Some("application/json".to_string()),
                ..Default::default()
            });
        });
    }
    
    /// 获取事件注解
    pub fn get_event_annotation(&self, key: &str) -> Option<String> {
        self.with_event_read(|ev| {
            ev.annotations.get(key).cloned()
        })
    }
    
    /// 获取事件级别
    pub fn get_event_level(&self) -> Level {
        self.with_event_read(|ev| ev.level.clone())
    }
    
    /// 设置事件阶段
    pub fn set_event_stage(&self, stage: audit_internal::Stage) {
        self.with_event_write(|mut ev| {
            ev.stage = stage;
        });
    }
    
    /// 获取事件阶段
    pub fn get_event_stage(&self) -> audit_internal::Stage {
        self.with_event_read(|ev| ev.stage.clone())
    }
    
    /// 设置事件阶段时间戳
    pub fn set_event_stage_timestamp(&self, timestamp: audit_internal::MicroTime) {
        self.with_event_write(|mut ev| {
            ev.stage_timestamp = timestamp;
        });
    }
    
    /// 获取事件响应状态
    pub fn get_event_response_status(&self) -> Option<audit_internal::Status> {
        self.with_event_read(|ev| ev.response_status.clone())
    }
    
    /// 获取事件请求接收时间戳
    pub fn get_event_request_received_timestamp(&self) -> audit_internal::MicroTime {
        self.with_event_read(|ev| ev.request_received_timestamp.clone())
    }
    
    /// 获取事件阶段时间戳
    pub fn get_event_stage_timestamp(&self) -> audit_internal::MicroTime {
        self.with_event_read(|ev| ev.stage_timestamp.clone())
    }
    
    /// 设置事件响应状态
    pub fn set_event_response_status(&self, status: Option<audit_internal::Status>) {
        self.with_event_write(|mut ev| {
            ev.response_status = status;
        });
    }
    
    /// 设置事件响应状态码
    pub fn set_event_response_status_code(&self, status_code: i32) {
        self.with_event_write(|mut ev| {
            if ev.response_status.is_none() {
                ev.response_status = Some(audit_internal::Status::default());
            }
            
            if let Some(ref mut status) = ev.response_status {
                status.code = Some(status_code);
            }
        });
    }
    
    /// 获取事件注解的克隆
    pub fn get_event_annotations(&self) -> HashMap<String, String> {
        self.with_event_read(|ev| ev.annotations.clone())
    }
    
    /// 添加审计注解（内部锁定版本）
    fn add_audit_annotation_locked(&self, key: String, value: String) {
        self.with_event_write(|mut ev| {
            if ev.annotations.contains_key(&key) && ev.annotations.get(&key) != Some(&value) {
                // 警告：注解已设置且值不同
                eprintln!(
                    "警告：无法将注解[{}]设置为'{}'，已设置为'{}'",
                    key,
                    value,
                    ev.annotations.get(&key).unwrap()
                );
                return;
            }
            ev.annotations.insert(key, value);
        });
    }
}

// ========== 错误类型 ==========

/// 上下文错误
#[derive(Debug)]
pub enum ContextError {
    AlreadyInitialized,
    NotInitialized,
    LockError(String),
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContextError::AlreadyInitialized => write!(f, "审计上下文已初始化"),
            ContextError::NotInitialized => write!(f, "审计上下文未初始化"),
            ContextError::LockError(msg) => write!(f, "锁错误: {}", msg),
        }
    }
}

impl std::error::Error for ContextError {}

// ========== 公共 API 函数 ==========

/// 添加审计注解
/// 
/// 在 WithAuditAnnotations 之后请求流的大部分位置安全调用。
/// 显著的例外是此函数不得在 WithAudit 之前运行的处理器中通过 defer 语句
/// （即在 ServeHTTP 之后）调用，因为此时审计事件已发送到审计 sink。
/// 不了解其在整体请求流中位置的处理程序应优先使用 AddAuditAnnotation
/// 而不是 LogAnnotation，以避免丢失注解。
pub fn add_audit_annotation(context: Arc<AuditContext>, key: String, value: String) {
    if !context.enabled() {
        return;
    }
    
    context.add_audit_annotation_locked(key, value);
}

/// AddAuditAnnotations 的批量版本。有关何时可调用的限制，请参阅 AddAuditAnnotation。
/// keys_and_values 是要添加的键值对，必须具有偶数个项目。
pub fn add_audit_annotations(context: Arc<AuditContext>, keys_and_values: Vec<String>) {
    if !context.enabled() {
        return;
    }
    
    if keys_and_values.len() % 2 != 0 {
        eprintln!("丢弃不匹配的审计注解 {:?}", keys_and_values.last().unwrap());
        return;
    }
    
    for i in (0..keys_and_values.len()).step_by(2) {
        let key = keys_and_values[i].clone();
        let value = keys_and_values[i + 1].clone();
        context.add_audit_annotation_locked(key, value);
    }
}

/// AddAuditAnnotation 的批量版本。有关何时可调用的限制，请参阅 AddAuditAnnotation。
pub fn add_audit_annotations_map(
    context: Arc<AuditContext>,
    annotations: HashMap<String, String>,
) {
    if !context.enabled() {
        return;
    }
    
    for (key, value) in annotations {
        context.add_audit_annotation_locked(key, value);
    }
}

/// 设置审计ID
/// 
/// # 参数
/// * `context` - 审计上下文
/// * `audit_id` - 审计ID，如果为空则不设置
pub fn with_audit_id(context: Arc<AuditContext>, audit_id: Option<String>) {
    if let Some(id) = audit_id {
        if !id.is_empty() {
            *context.audit_id.lock().unwrap() = Some(id.clone());
            context.with_event_write(|mut ev| {
                ev.audit_id = id;
            });
        }
    }
}

/// 获取审计ID（截断版本）
/// 
/// 如果 Audit-ID 值的长度超过限制，我们将其截断以保留前N个字符。
/// 这仅用于日志记录。
pub fn get_audit_id_truncated(context: Arc<AuditContext>) -> String {
    const MAX_AUDIT_ID_LENGTH: usize = 64;
    
    let audit_id = match context.audit_id.lock().unwrap().as_ref() {
        Some(id) => id.clone(),
        None => return String::new(),
    };
    
    // 如果用户指定了非常长的审计ID，则使用前N个字符
    // 注意：假设 Audit-ID 头部是ASCII
    if audit_id.len() > MAX_AUDIT_ID_LENGTH {
        audit_id[..MAX_AUDIT_ID_LENGTH].to_string()
    } else {
        audit_id
    }
}

/// 为审计上下文实现 Debug
impl fmt::Debug for AuditContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditContext")
            .field("initialized", &self.initialized.load(Ordering::Relaxed))
            .field("audit_id", &self.audit_id.lock().unwrap())
            .finish()
    }
}