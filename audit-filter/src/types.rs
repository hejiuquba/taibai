//! 公共类型定义

use std::time::{Duration, SystemTime};

/// 审计阶段
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditStage {
    /// 请求接收
    RequestReceived,
    /// 响应开始（长请求）
    ResponseStarted,
    /// 响应完成
    ResponseComplete,
    /// 发生 Panic
    Panic,
}

/// HTTP 状态码包装，避免直接依赖 http
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCode(u16);

impl StatusCode {
    pub fn from_u16(code: u16) -> Option<Self> {
        if code >= 100 && code <= 599 {
            Some(Self(code))
        } else {
            None
        }
    }
    
    pub fn as_u16(&self) -> u16 {
        self.0
    }
    
    // 常用状态码
    pub const OK: StatusCode = StatusCode(200);
    pub const NOT_FOUND: StatusCode = StatusCode(404);
    pub const INTERNAL_SERVER_ERROR: StatusCode = StatusCode(500);
    pub const UNAUTHORIZED: StatusCode = StatusCode(401);
}

/// 审计事件
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// 事件唯一 ID
    pub event_id: String,
    /// 审计阶段
    pub stage: AuditStage,
    /// HTTP 状态码
    pub status: Option<StatusCode>,
    /// 请求延迟
    pub latency: Duration,
    /// 时间戳
    pub timestamp: SystemTime,
    /// 请求路径
    pub path: String,
    /// 请求方法
    pub method: String,
}

impl AuditEvent {
    pub fn new(
        event_id: String,
        stage: AuditStage,
        status: Option<StatusCode>,
        latency: Duration,
        path: String,
        method: String,
    ) -> Self {
        Self {
            event_id,
            stage,
            status,
            latency,
            timestamp: SystemTime::now(),
            path,
            method,
        }
    }
}