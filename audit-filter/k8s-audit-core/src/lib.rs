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

//! Kubernetes审计日志核心模块
//!
//! 此crate提供了Kubernetes审计系统的核心功能，包括：
//! - 审计事件处理
//! - 策略评估和检查
//! - 请求审计
//! - 多种输出格式
//!
//! # 示例
//! ```
//! use k8s_audit_core::context::AuditContext;
//! use k8s_audit_core::format::event_string;
//! use k8s_audit_apis::audit;
//!
//! // 创建审计上下文
//! let context = AuditContext::new();
//!
//! // 创建审计事件
//! let event = audit::Event {
//!     audit_id: "test-id".to_string(),
//!     verb: "GET".to_string(),
//!     ..Default::default()
//! };
//!
//! // 格式化事件
//! let formatted = event_string(&event);
//! ```

// 公开的模块
pub mod context;
pub mod evaluator;
pub mod format;
pub mod request;
pub mod types;
pub mod union;

// 策略模块
pub mod policy {
    pub mod checker;
    pub mod reader;
    pub mod util;
}

// 重新导出常用类型
pub use context::{AuditContext, RequestAuditConfig};
pub use evaluator::{AuthorizerAttributes, PolicyRuleEvaluator};
pub use types::{Backend, BackendError, Sink, SinkError};

// 预导入模块
pub mod prelude {
    pub use crate::context::{AuditContext, RequestAuditConfig};
    pub use crate::evaluator::{AuthorizerAttributes, PolicyRuleEvaluator};
    pub use crate::format::{event_string, event_string_multiline};
    pub use crate::request::{log_request_metadata, log_request_object};
    pub use crate::types::{Backend, BackendError, Sink, SinkError};
    pub use crate::union::union_backend;
    
    pub use k8s_audit_apis::audit;
}