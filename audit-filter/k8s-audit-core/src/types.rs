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
limitations under the above.
*/

//! 审计类型定义
//! 
//! 此模块定义了审计系统的核心接口。

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use k8s_audit_apis::audit as audit_internal;

// ========== 错误类型定义（标准库实现） ==========

/// 事件处理器错误
#[derive(Debug)]
pub struct SinkError {
    message: String,
    cause: Option<Box<dyn Error + Send + Sync>>,
}

impl SinkError {
    /// 创建新的 SinkError
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            cause: None,
        }
    }
    
    /// 创建带原因的 SinkError
    pub fn with_cause(message: impl Into<String>, cause: Box<dyn Error + Send + Sync>) -> Self {
        Self {
            message: message.into(),
            cause: Some(cause),
        }
    }
}

impl fmt::Display for SinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sink错误: {}", self.message)
    }
}

impl Error for SinkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause.as_ref().map(|c| c.as_ref() as &(dyn Error + 'static))
    }
}

/// 后端错误
#[derive(Debug)]
pub struct BackendError {
    message: String,
    cause: Option<Box<dyn Error + Send + Sync>>,
}

impl BackendError {
    /// 创建新的 BackendError
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            cause: None,
        }
    }
    
    /// 创建带原因的 BackendError
    pub fn with_cause(message: impl Into<String>, cause: Box<dyn Error + Send + Sync>) -> Self {
        Self {
            message: message.into(),
            cause: Some(cause),
        }
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "后端错误: {}", self.message)
    }
}

impl Error for BackendError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause.as_ref().map(|c| c.as_ref() as &(dyn Error + 'static))
    }
}

// ========== 核心接口定义 ==========

/// Sink 接口表示事件处理器
/// 
/// 每个审计ID可能调用 process_events 最多三次。
/// 错误可能由 sink 自身记录。如果错误应该是致命的，导致内部错误，
/// process_events 应该 panic。
/// 
/// 事件不能被修改，调用者在调用返回后会重用事件，
/// 即 sink 必须进行深拷贝以保留副本（如果需要）。
/// 
/// 成功时返回 true，错误时可能返回 false。
pub trait Sink: Send + Sync + 'static {
    /// 处理事件
    /// 
    /// # 参数
    /// * `events` - 要处理的事件切片，使用 Arc 支持零拷贝共享
    /// 
    /// # 返回值
    /// 成功时返回 true，错误时可能返回 false
    /// 
    /// # 注意
    /// 实现应避免阻塞，事件处理应尽快完成。
    /// 如果需要进行 I/O 操作，应考虑使用后台线程或异步处理。
    fn process_events(&self, events: &[Arc<audit_internal::Event>]) -> bool;
    
    /// 处理单个事件的便捷方法
    fn process_event(&self, event: Arc<audit_internal::Event>) -> bool {
        self.process_events(&[event])
    }
}

/// Backend 接口表示审计后端
/// 
/// 后端必须实现 Sink 接口，并添加生命周期管理和标识功能。
pub trait Backend: Sink {
    /// 初始化后端
    /// 
    /// 不能阻塞，但可以在后台运行线程。
    /// 如果 stop_rx 接收到信号，应该停止后台线程。
    /// 在第一次调用 process_events 之前会调用 run。
    /// 
    /// # 参数
    /// * `stop_rx` - 停止信号接收器，收到信号时表示后端应该停止
    /// 
    /// # 返回值
    /// 初始化结果
    /// 
    /// # 注意
    /// 实现应该尽快返回，将长时间运行的任务放在后台线程。
    fn run(&self, stop_rx: std::sync::mpsc::Receiver<()>) -> Result<(), BackendError>;
    
    /// 同步关闭后端，同时确保所有挂起的事件都被传递
    /// 
    /// 可以假设在传递给 run 方法的 stop_rx 接收到信号后调用此方法。
    /// 
    /// # 注意
    /// 此方法应阻塞直到所有待处理事件完成。
    fn shutdown(&self);
    
    /// 返回后端插件名称
    fn name(&self) -> &str;
    
    /// 检查后端是否健康
    /// 
    /// # 返回值
    /// 健康时返回 true，否则返回 false
    fn is_healthy(&self) -> bool {
        true
    }
}

/// 后端构建器 trait
/// 
/// 用于构建和配置后端实例
pub trait BackendBuilder: Send + Sync + 'static {
    /// 构建后端实例
    fn build(self: Box<Self>) -> Result<Box<dyn Backend>, BackendError>;
    
    /// 获取构建器名称
    fn name(&self) -> &str;
}

// ========== 工具函数和类型 ==========

/// 空的停止信号发送器
/// 
/// 用于不需要停止信号的后端
pub fn noop_stop_signal() -> std::sync::mpsc::Receiver<()> {
    let (_tx, rx) = std::sync::mpsc::channel();
    rx
}

/// 简单的错误转换
impl From<String> for SinkError {
    fn from(s: String) -> Self {
        SinkError::new(s)
    }
}

impl From<&str> for SinkError {
    fn from(s: &str) -> Self {
        SinkError::new(s)
    }
}

impl From<String> for BackendError {
    fn from(s: String) -> Self {
        BackendError::new(s)
    }
}

impl From<&str> for BackendError {
    fn from(s: &str) -> Self {
        BackendError::new(s)
    }
}