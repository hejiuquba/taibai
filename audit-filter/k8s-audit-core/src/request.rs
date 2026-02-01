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

//! 请求审计
//!
//! 此模块提供了记录HTTP请求和响应审计信息的函数。

use std::collections::HashMap;
use std::time::SystemTime;

use k8s_audit_apis::audit as audit_internal;
use k8s_audit_apis::LevelExt;

use crate::context::AuditContext;
use crate::evaluator::AuthorizerAttributes;

/// 最大User-Agent长度
const MAX_USER_AGENT_LENGTH: usize = 1024;

/// User-Agent截断后缀
const USER_AGENT_TRUNCATE_SUFFIX: &str = "...TRUNCATED";

/// HTTP请求trait（简化版本）
pub trait HttpRequest {
    /// 获取请求URI
    fn uri(&self) -> &str;
    
    /// 获取User-Agent
    fn user_agent(&self) -> Option<&str>;
    
    /// 获取远程地址
    fn remote_addr(&self) -> Option<&str>;
    
    /// 获取请求头
    fn headers(&self) -> &HashMap<String, String>;
}

/// 记录请求元数据到审计事件
pub fn log_request_metadata(
    context: &AuditContext,
    request: &impl HttpRequest,
    request_received_timestamp: SystemTime,
    attrs: &dyn AuthorizerAttributes,
) {
    if !context.enabled() {
        return;
    }
    
    context.with_event_write(|mut event| {
        // 设置请求接收时间戳
        event.request_received_timestamp = audit_internal::MicroTime::from_system_time(
            request_received_timestamp
        );
        
        // 设置动词
        event.verb = attrs.get_verb().to_string();
        
        // 设置请求URI
        event.request_uri = request.uri().to_string();
        
        // 设置User-Agent（可能截断）
        event.user_agent = Some(maybe_truncate_user_agent(request));
        
        // 设置源IP地址
        event.source_ips = get_source_ips(request);
        
        // 设置用户信息
        if let Some(username) = attrs.get_user() {
            event.user.username = Some(username.to_string());
            event.user.groups = Some(attrs.get_groups());
            event.user.extra = Some(std::collections::BTreeMap::new());
            event.user.uid = Some("".to_string());
        }
        
        // 如果是资源请求，设置对象引用
        if attrs.is_resource_request() {
            event.object_ref = Some(audit_internal::ObjectReference {
                namespace: attrs.get_namespace().map(|s| s.to_string()),
                name: attrs.get_name().map(|s| s.to_string()),
                resource: attrs.get_resource().map(|s| s.to_string()),
                subresource: attrs.get_subresource().map(|s| s.to_string()),
                api_group: attrs.get_api_group().map(|s| s.to_string()),
                api_version: attrs.get_api_version().map(|s| s.to_string()),
                ..Default::default()
            });
        }
    });
}

/// 记录被模拟的用户信息到审计事件
pub fn log_impersonated_user(context: &AuditContext, user_info: crate::context::UserInfo) {
    if !context.enabled() {
        return;
    }
    
    context.log_impersonated_user(user_info);
}

/// 记录请求对象到审计事件
pub fn log_request_object(
    context: &AuditContext,
    request_object: Option<audit_internal::Unknown>,
) {
    if !context.enabled() {
        return;
    }
    
    if context.get_event_level().less(&audit_internal::Level::Metadata) {
        return;
    }
    
    context.with_event_write(|mut event| {
        if !event.level.less(&audit_internal::Level::Request) {
            event.request_object = request_object;
        }
    });
}

/// 记录请求补丁到审计事件
pub fn log_request_patch(context: &AuditContext, patch: Vec<u8>) {
    if context.get_event_level().less(&audit_internal::Level::Request) {
        return;
    }
    
    context.log_request_patch(patch);
}

/// 记录响应对象到审计事件
pub fn log_response_object(
    context: &AuditContext,
    status: Option<&audit_internal::Status>,
    response_object: Option<audit_internal::Unknown>,
) {
    let level = context.get_event_level();
    
    if level.less(&audit_internal::Level::Metadata) {
        return;
    } else if level.less(&audit_internal::Level::RequestResponse) {
        context.log_response_object(status, None);
        return;
    }
    
    context.log_response_object(status, response_object.as_ref());
}

/// 截断User-Agent（如果太长），否则直接返回
fn maybe_truncate_user_agent(request: &impl HttpRequest) -> String {
    let user_agent = request.user_agent().unwrap_or("");
    
    if user_agent.len() > MAX_USER_AGENT_LENGTH {
        let truncated = &user_agent[..MAX_USER_AGENT_LENGTH];
        format!("{}{}", truncated, USER_AGENT_TRUNCATE_SUFFIX)
    } else {
        user_agent.to_string()
    }
}

/// 获取请求的源IP地址
fn get_source_ips(request: &impl HttpRequest) -> Vec<String> {
    let mut ips = Vec::new();
    
    if let Some(ip) = request.remote_addr() {
        ips.push(ip.to_string());
    }
    
    if let Some(xff) = request.headers().get("X-Forwarded-For") {
        for ip in xff.split(',') {
            let trimmed = ip.trim();
            if !trimmed.is_empty() {
                ips.push(trimmed.to_string());
            }
        }
    }
    
    ips
}

/// 检查是否应该省略托管字段
fn should_omit_managed_fields(_context: &AuditContext) -> bool {
    false
}

// 移除复杂的 KubernetesObject trait 和相关函数
// 简化测试

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    
    // 模拟HTTP请求
    #[derive(Debug)]
    struct MockHttpRequest {
        uri: String,
        user_agent: Option<String>,
        remote_addr: Option<String>,
        headers: HashMap<String, String>,
    }
    
    impl MockHttpRequest {
        fn new(uri: &str, user_agent: Option<&str>) -> Self {
            let mut headers = HashMap::new();
            if let Some(ua) = user_agent {
                headers.insert("User-Agent".to_string(), ua.to_string());
            }
            
            Self {
                uri: uri.to_string(),
                user_agent: user_agent.map(|s| s.to_string()),
                remote_addr: Some("192.168.1.1:8080".to_string()),
                headers,
            }
        }
        
        fn with_xff(mut self, xff: &str) -> Self {
            self.headers.insert("X-Forwarded-For".to_string(), xff.to_string());
            self
        }
    }
    
    impl HttpRequest for MockHttpRequest {
        fn uri(&self) -> &str {
            &self.uri
        }
        
        fn user_agent(&self) -> Option<&str> {
            self.user_agent.as_deref()
        }
        
        fn remote_addr(&self) -> Option<&str> {
            self.remote_addr.as_deref()
        }





















        
        fn headers(&self) -> &HashMap<String, String> {
            &self.headers
        }
    }
    
    #[test]
    fn test_maybe_truncate_user_agent_short() {
        let request = MockHttpRequest::new("/test", Some("ShortAgent"));
        let result = maybe_truncate_user_agent(&request);
        assert_eq!(result, "ShortAgent");
    }
    
    #[test]
    fn test_maybe_truncate_user_agent_long() {
        let long_agent = "A".repeat(MAX_USER_AGENT_LENGTH + 100);
        let request = MockHttpRequest::new("/test", Some(&long_agent));
        let result = maybe_truncate_user_agent(&request);
        
        assert!(result.len() <= MAX_USER_AGENT_LENGTH + USER_AGENT_TRUNCATE_SUFFIX.len());
        assert!(result.ends_with(USER_AGENT_TRUNCATE_SUFFIX));
    }
    
    #[test]
    fn test_get_source_ips() {
        let request = MockHttpRequest::new("/test", None)
            .with_xff("192.168.1.2, 192.168.1.3, 192.168.1.4");
        
        let ips = get_source_ips(&request);
        
        assert!(ips.contains(&"192.168.1.1:8080".to_string()));
        assert!(ips.contains(&"192.168.1.2".to_string()));
        assert!(ips.contains(&"192.168.1.3".to_string()));
        assert!(ips.contains(&"192.168.1.4".to_string()));
    }
}