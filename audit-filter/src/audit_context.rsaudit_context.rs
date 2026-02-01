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
limitations under the License.
*/

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

// 类型定义
pub type UID = String;
pub type MicroTime = u64;

// 审计级别
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    None,
    Metadata,
    Request,
    RequestResponse,
}

impl Level {
    pub fn less(&self, other: Level) -> bool {
        (*self as i32) < (other as i32)
    }
}

// 阶段
pub type Stage = String;

// 状态
#[derive(Debug, Clone)]
pub struct Status {
    pub status: String,
    pub message: String,
    pub reason: String,
    pub details: Option<String>,
    pub code: i32,
}

// 未知对象
#[derive(Debug, Clone)]
pub struct Unknown {
    pub raw: Vec<u8>,
    pub content_type: String,
}

// 用户信息
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    pub uid: Option<String>,
    pub groups: Vec<String>,
    pub extra: HashMap<String, Vec<String>>,
}

impl UserInfo {
    pub fn deep_copy(&self) -> Self {
        self.clone()
    }
}

// 认证元数据
#[derive(Debug, Clone)]
pub struct AuthenticationMetadata {
    pub impersonation_constraint: Option<String>,
}

// 审计事件
#[derive(Debug, Clone)]
pub struct Event {
    pub audit_id: UID,
    pub level: Level,
    pub stage: Stage,
    pub stage_timestamp: MicroTime,
    pub request_received_timestamp: MicroTime,
    pub user: Option<UserInfo>,
    pub impersonated_user: Option<UserInfo>,
    pub annotations: HashMap<String, String>,
    pub response_status: Option<Status>,
    pub response_object: Option<Unknown>,
    pub request_object: Option<Unknown>,
    pub authentication_metadata: Option<AuthenticationMetadata>,
}

impl Event {
    pub fn new() -> Self {
        let now = current_micro_time();
        Self {
            audit_id: String::new(),
            level: Level::None,
            stage: "ResponseStarted".to_string(),
            stage_timestamp: now,
            request_received_timestamp: now,
            user: None,
            impersonated_user: None,
            annotations: HashMap::new(),
            response_status: None,
            response_object: None,
            request_object: None,
            authentication_metadata: None,
        }
    }
}

// 审计配置
#[derive(Debug, Clone)]
pub struct RequestAuditConfig {
    pub level: Level,
    pub omit_stages: Vec<Stage>,
}

// 接收器trait
pub trait Sink: Send + Sync {
    fn process_events(&self, event: &Event) -> bool;
}

// 上下文键
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContextKey(i32);

impl ContextKey {
    pub const AUDIT_KEY: ContextKey = ContextKey(0);
}

// 主审计上下文结构
pub struct AuditContext {
    // 原子状态标志
    initialized: AtomicBool,
    
    // 配置和接收器（互斥锁保护）
    request_audit_config: Mutex<Option<RequestAuditConfig>>,
    sink: Mutex<Option<Arc<dyn Sink>>>,
    
    // 事件数据（互斥锁保护）
    event: Mutex<Event>,
    
    // 原子存储的audit_id（快速读取）
    audit_id: AtomicU32,
}

impl AuditContext {
    // 创建新的审计上下文（包装在Arc中以便共享）
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            initialized: AtomicBool::new(false),
            request_audit_config: Mutex::new(None),
            sink: Mutex::new(None),
            event: Mutex::new(Event::new()),
            audit_id: AtomicU32::new(0),
        })
    }
    
    // 检查审计是否启用
    pub fn enabled(&self) -> bool {
        if !self.initialized.load(Ordering::Acquire) {
            // 注意：未设置的Level应视为启用，以便在评估审计策略之前仍可捕获请求数据
            return true;
        }
        
        let config = self.request_audit_config.lock().unwrap();
        match &*config {
            Some(cfg) => cfg.level != Level::None,
            None => true,
        }
    }
    
    // 初始化审计上下文
    pub fn init(
        &self,
        request_audit_config: RequestAuditConfig,
        sink: Arc<dyn Sink>,
    ) -> Result<(), String> {
        // 获取所有需要的锁
        let mut config_lock = self.request_audit_config.lock().unwrap();
        let mut sink_lock = self.sink.lock().unwrap();
        let mut event_lock = self.event.lock().unwrap();
        
        if self.initialized.load(Ordering::Acquire) {
            return Err("audit context was already initialized".to_string());
        }
        
        // 设置配置
        *config_lock = Some(request_audit_config.clone());
        *sink_lock = Some(sink);
        
        // 更新事件级别
        event_lock.level = request_audit_config.level;
        
        self.initialized.store(true, Ordering::Release);
        Ok(())
    }
    
    // 获取审计ID
    pub fn audit_id(&self) -> UID {
        self.audit_id.load(Ordering::Acquire).to_string()
    }
    
    // 访问事件（对应Go的visitEvent）
    pub fn visit_event<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Event) -> R,
    {
        let mut event = self.event.lock().unwrap();
        f(&mut event)
    }
    
    // 处理事件阶段
    pub fn process_event_stage(&self, stage: Stage) -> bool {
        if !self.initialized.load(Ordering::Acquire) {
            return true;
        }
        
        // 检查sink
        let sink = {
            let sink_lock = self.sink.lock().unwrap();
            sink_lock.clone()
        };
        
        if sink.is_none() {
            return true;
        }
        
        // 检查是否应跳过
        let should_omit = {
            let config_lock = self.request_audit_config.lock().unwrap();
            if let Some(config) = &*config_lock {
                config.omit_stages.contains(&stage)
            } else {
                false
            }
        };
        
        if should_omit {
            return true;
        }
        
        let processed = self.visit_event(|event| {
            event.stage = stage.clone();
            
            if stage == "RequestReceived" {
                event.stage_timestamp = event.request_received_timestamp;
            } else {
                event.stage_timestamp = current_micro_time();
            }
            
            // 调用接收器处理事件
            if let Some(s) = &sink {
                s.process_events(event)
            } else {
                true
            }
        });
        
        processed
    }
    
    // 记录模拟用户
    pub fn log_impersonated_user(&self, user: &dyn User, constraint: Option<&str>) {
        self.visit_event(|ev| {
            if ev.level.less(Level::Metadata) {
                return;
            }
            
            let mut impersonated_user = UserInfo {
                username: user.get_name().to_string(),
                uid: user.get_uid().map(|s| s.to_string()),
                groups: user.get_groups().to_vec(),
                extra: user.get_extra().clone(),
            };
            
            ev.impersonated_user = Some(impersonated_user);
            
            if let Some(constraint_str) = constraint {
                ev.authentication_metadata = Some(AuthenticationMetadata {
                    impersonation_constraint: Some(constraint_str.to_string()),
                });
            }
        });
    }
    
    // 记录响应对象
    pub fn log_response_object(&self, status: Option<&Status>, obj: Option<&Unknown>) {
        self.visit_event(|ae| {
            if let Some(status) = status {
                ae.response_status = Some(Status {
                    status: status.status.clone(),
                    message: status.message.clone(),
                    reason: status.reason.clone(),
                    details: status.details.clone(),
                    code: status.code,
                });
            }
            
            if ae.level.less(Level::RequestResponse) {
                return;
            }
            
            if let Some(obj) = obj {
                ae.response_object = Some(obj.clone());
            }
        });
    }
    
    // 记录请求补丁
    pub fn log_request_patch(&self, patch: Vec<u8>) {
        self.visit_event(|ae| {
            ae.request_object = Some(Unknown {
                raw: patch,
                content_type: "application/json".to_string(),
            });
        });
    }
    
    // 获取事件用户
    pub fn get_event_user(&self) -> Option<UserInfo> {
        let mut result = None;
        self.visit_event(|ev| {
            result = ev.user.clone();
        });
        result
    }
    
    // 获取事件模拟用户
    pub fn get_event_impersonated_user(&self) -> Option<UserInfo> {
        let mut result = None;
        self.visit_event(|ev| {
            result = ev.impersonated_user.clone();
        });
        result
    }
    
    // 获取事件注解
    pub fn get_event_annotation(&self, key: &str) -> Option<String> {
        let mut result = None;
        self.visit_event(|event| {
            result = event.annotations.get(key).cloned();
        });
        result
    }
    
    // 获取事件级别
    pub fn get_event_level(&self) -> Level {
        let mut result = Level::None;
        self.visit_event(|event| {
            result = event.level;
        });
        result
    }
    
    // 设置事件阶段
    pub fn set_event_stage(&self, stage: Stage) {
        self.visit_event(|event| {
            event.stage = stage;
        });
    }
    
    // 获取事件阶段
    pub fn get_event_stage(&self) -> Stage {
        let mut result = String::new();
        self.visit_event(|event| {
            result = event.stage.clone();
        });
        result
    }
    
    // 设置事件阶段时间戳
    pub fn set_event_stage_timestamp(&self, timestamp: MicroTime) {
        self.visit_event(|event| {
            event.stage_timestamp = timestamp;
        });
    }
    
    // 获取事件响应状态
    pub fn get_event_response_status(&self) -> Option<Status> {
        let mut result = None;
        self.visit_event(|event| {
            result = event.response_status.clone();
        });
        result
    }
    
    // 获取事件请求接收时间戳
    pub fn get_event_request_received_timestamp(&self) -> MicroTime {
        let mut result = 0;
        self.visit_event(|event| {
            result = event.request_received_timestamp;
        });
        result
    }
    
    // 获取事件阶段时间戳
    pub fn get_event_stage_timestamp(&self) -> MicroTime {
        let mut result = 0;
        self.visit_event(|event| {
            result = event.stage_timestamp;
        });
        result
    }
    
    // 设置事件响应状态
    pub fn set_event_response_status(&self, status: Option<Status>) {
        self.visit_event(|event| {
            event.response_status = status;
        });
    }
    
    // 设置事件响应状态码
    pub fn set_event_response_status_code(&self, status_code: i32) {
        self.visit_event(|event| {
            if event.response_status.is_none() {
                event.response_status = Some(Status {
                    status: String::new(),
                    message: String::new(),
                    reason: String::new(),
                    details: None,
                    code: 0,
                });
            }
            
            if let Some(status) = &mut event.response_status {
                status.code = status_code;
            }
        });
    }
    
    // 获取事件所有注解
    pub fn get_event_annotations(&self) -> HashMap<String, String> {
        let mut result = HashMap::new();
        self.visit_event(|event| {
            result = event.annotations.clone();
        });
        result
    }
    
    // 添加审计注解（内部方法）
    fn add_audit_annotation_locked(&self, key: String, value: String) {
        self.visit_event(|ae| {
            if ae.annotations.is_none() {
                ae.annotations = HashMap::new();
            }
            
            if let Some(existing) = ae.annotations.get(&key) {
                if existing != &value {
                    eprintln!("Warning: Failed to set annotations[{:?}] to {:?} for audit:{:?}, it has already been set to {:?}", 
                             key, value, ae.audit_id, ae.annotations.get(&key));
                    return;
                }
            }
            ae.annotations.insert(key, value);
        });
    }
    
    // 设置审计ID
    pub fn set_audit_id(&self, audit_id: UID) {
        if audit_id.is_empty() {
            return;
        }
        
        // 计算哈希值作为原子存储
        let id_hash = audit_id
            .bytes()
            .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
        
        self.audit_id.store(id_hash, Ordering::Release);
        
        self.visit_event(|event| {
            event.audit_id = audit_id.clone();
        });
    }
    
    // 获取截断的审计ID
    pub fn get_audit_id_truncated(&self) -> String {
        let audit_id = {
            let event = self.event.lock().unwrap();
            event.audit_id.clone()
        };
        
        const MAX_AUDIT_ID_LENGTH: usize = 64;
        if audit_id.len() > MAX_AUDIT_ID_LENGTH {
            audit_id[..MAX_AUDIT_ID_LENGTH].to_string()
        } else {
            audit_id
        }
    }
}

// 用户trait（模拟Go的user.Info）
pub trait User {
    fn get_name(&self) -> &str;
    fn get_uid(&self) -> Option<&str>;
    fn get_groups(&self) -> &[String];
    fn get_extra(&self) -> &HashMap<String, Vec<String>>;
}

// 观察事件（占位函数）
pub fn observe_event() {
    // 实现事件观察逻辑
}

// 上下文管理函数

// 添加审计注解
pub fn add_audit_annotation(ctx: Option<&AuditContext>, key: &str, value: &str) {
    if let Some(ac) = ctx {
        if !ac.enabled() {
            return;
        }
        
        ac.add_audit_annotation_locked(key.to_string(), value.to_string());
    }
}

// 批量添加审计注解
pub fn add_audit_annotations(ctx: Option<&AuditContext>, keys_and_values: &[(&str, &str)]) {
    if let Some(ac) = ctx {
        if !ac.enabled() {
            return;
        }
        
        if keys_and_values.len() % 2 != 0 {
            eprintln!("Dropping mismatched audit annotation {:?}", 
                     keys_and_values.last().unwrap());
        }
        
        for i in (0..keys_and_values.len()).step_by(2) {
            if i + 1 < keys_and_values.len() {
                ac.add_audit_annotation_locked(
                    keys_and_values[i].0.to_string(),
                    keys_and_values[i].1.to_string(),
                );
            }
        }
    }
}

// 从映射添加审计注解
pub fn add_audit_annotations_map(ctx: Option<&AuditContext>, annotations: &HashMap<String, String>) {
    if let Some(ac) = ctx {
        if !ac.enabled() {
            return;
        }
        
        for (k, v) in annotations {
            ac.add_audit_annotation_locked(k.clone(), v.clone());
        }
    }
}

// 模拟上下文类型
#[derive(Debug)]
pub struct Context {
    values: HashMap<String, Box<dyn std::any::Any + Send + Sync>>,
}

impl Context {
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }
    
    pub fn with_value(mut self, key: ContextKey, value: Arc<AuditContext>) -> Self {
        self.values.insert(key.0.to_string(), Box::new(value));
        self
    }
    
    pub fn value(&self, key: ContextKey) -> Option<&Arc<AuditContext>> {
        self.values
            .get(&key.0.to_string())
            .and_then(|boxed| boxed.downcast_ref::<Arc<AuditContext>>())
    }
}

// 带审计上下文返回新上下文
pub fn with_audit_context(parent: Context) -> Context {
    if parent.value(ContextKey::AUDIT_KEY).is_some() {
        return parent; // 避免重复注册
    }
    
    let audit_context = AuditContext::new();
    parent.with_value(ContextKey::AUDIT_KEY, audit_context)
}

// 从上下文获取审计上下文
pub fn audit_context_from(ctx: &Context) -> Option<&Arc<AuditContext>> {
    ctx.value(ContextKey::AUDIT_KEY)
}

// 设置审计ID
pub fn with_audit_id(ctx: &Context, audit_id: UID) {
    if audit_id.is_empty() {
        return;
    }
    
    if let Some(ac) = audit_context_from(ctx) {
        ac.set_audit_id(audit_id);
    }
}

// 从上下文获取审计ID
pub fn audit_id_from(ctx: &Context) -> (UID, bool) {
    if let Some(ac) = audit_context_from(ctx) {
        (ac.audit_id(), true)
    } else {
        (String::new(), false)
    }
}

// 获取截断的审计ID
pub fn get_audit_id_truncated(ctx: &Context) -> String {
    let (audit_id, ok) = audit_id_from(ctx);
    if !ok {
        return String::new();
    }
    
    const MAX_AUDIT_ID_LENGTH: usize = 64;
    if audit_id.len() > MAX_AUDIT_ID_LENGTH {
        audit_id[..MAX_AUDIT_ID_LENGTH].to_string()
    } else {
        audit_id
    }
}

// 辅助函数
fn current_micro_time() -> MicroTime {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    
    struct TestUser {
        name: String,
        uid: Option<String>,
        groups: Vec<String>,
        extra: HashMap<String, Vec<String>>,
    }
    
    impl User for TestUser {
        fn get_name(&self) -> &str {
            &self.name
        }
        
        fn get_uid(&self) -> Option<&str> {
            self.uid.as_deref()
        }
        
        fn get_groups(&self) -> &[String] {
            &self.groups
        }
        
        fn get_extra(&self) -> &HashMap<String, Vec<String>> {
            &self.extra
        }
    }
    
    struct TestSink {
        processed: StdMutex<usize>,
    }
    
    impl TestSink {
        fn new() -> Self {
            Self {
                processed: StdMutex::new(0),
            }
        }
    }
    
    impl Sink for TestSink {
        fn process_events(&self, _event: &Event) -> bool {
            let mut count = self.processed.lock().unwrap();
            *count += 1;
            true
        }
    }
    
    #[test]
    fn test_audit_context_basic() {
        let ctx = AuditContext::new();
        
        assert!(!ctx.initialized.load(Ordering::Acquire));
        assert!(ctx.enabled()); // 未初始化时默认启用
        
        let config = RequestAuditConfig {
            level: Level::Metadata,
            omit_stages: vec!["ResponseComplete".to_string()],
        };
        
        let sink = Arc::new(TestSink::new());
        
        // 初始化
        assert!(ctx.init(config.clone(), Arc::clone(&sink)).is_ok());
        assert!(ctx.initialized.load(Ordering::Acquire));
        
        // 重复初始化应失败
        assert!(ctx.init(config, Arc::new(TestSink::new())).is_err());
    }
    
    #[test]
    fn test_audit_annotations() {
        let ctx = AuditContext::new();
        
        // 添加注解
        add_audit_annotation(Some(&ctx), "key1", "value1");
        add_audit_annotation(Some(&ctx), "key2", "value2");
        
        // 获取注解
        let annotation = ctx.get_event_annotation("key1");
        assert_eq!(annotation, Some("value1".to_string()));
        
        // 批量添加
        add_audit_annotations(Some(&ctx), &[("key3", "value3"), ("key4", "value4")]);
        
        let annotations = ctx.get_event_annotations();
        assert!(annotations.contains_key("key3"));
        assert!(annotations.contains_key("key4"));
    }
    
    #[test]
    fn test_log_impersonated_user() {
        let ctx = AuditContext::new();
        
        // 初始化
        let config = RequestAuditConfig {
            level: Level::Metadata,
            omit_stages: vec![],
        };
        
        ctx.init(config, Arc::new(TestSink::new())).unwrap();
        
        // 设置级别为Metadata
        ctx.visit_event(|event| {
            event.level = Level::Metadata;
        });
        
        // 创建测试用户
        let test_user = TestUser {
            name: "testuser".to_string(),
            uid: Some("12345".to_string()),
            groups: vec!["group1".to_string(), "group2".to_string()],
            extra: {
                let mut map = HashMap::new();
                map.insert("extra1".to_string(), vec!["value1".to_string()]);
                map
            },
        };
        
        // 记录模拟用户
        ctx.log_impersonated_user(&test_user, Some("constraint1"));
        
        let impersonated = ctx.get_event_impersonated_user();
        assert!(impersonated.is_some());
        let user = impersonated.unwrap();
        assert_eq!(user.username, "testuser");
        assert_eq!(user.uid, Some("12345".to_string()));
    }
}
