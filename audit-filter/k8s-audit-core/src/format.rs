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

//! 审计事件格式化
//!
//! 此模块提供了审计事件的文本格式化功能。

use k8s_audit_apis::audit as audit_internal;

/// 为缺失的值提供的默认字符串
const NONE: &str = "<none>";
const SELF: &str = "<self>";
const LOOKUP: &str = "<lookup>";
const UNKNOWN: &str = "<unknown>";
const DEFERRED: &str = "<deferred>";

/// 创建审计事件的单行文本表示，使用事件结构中的部分信息
/// 
/// # 参数
/// * `ev` - 审计事件
/// 
/// # 返回值
/// 格式化后的字符串
/// 
/// # 示例
/// ```
/// use k8s_audit_core::format::event_string;
/// use k8s_audit_apis::audit;
/// 
/// let event = audit::Event {
///     audit_id: "test-id".to_string(),
///     stage: audit::Stage::RequestReceived,
///     verb: "GET".to_string(),
///     request_uri: "/api/v1/pods".to_string(),
///     ..Default::default()
/// };
/// 
/// let formatted = event_string(&event);
/// assert!(formatted.contains("AUDIT:"));
/// ```
pub fn event_string(ev: &audit_internal::Event) -> String {
    // 用户名和组
    let (username, groups) = get_user_info(ev);
    
    // 模拟用户和模拟组
    let (asuser, asgroups) = get_impersonated_user_info(ev);
    
    // 命名空间
    let namespace = get_namespace(ev);
    
    // 响应状态
    let response = get_response_status(ev);
    
    // 源IP
    let ip = get_source_ip(ev);
    
    // 格式化时间戳
    let timestamp = format_timestamp(&ev.request_received_timestamp);
    
    format!(
        "{} AUDIT: id={:?} stage={:?} ip={:?} method={:?} user={:?} groups={} as={:?} asgroups={} user-agent={:?} namespace={:?} uri={:?} response={:?}",
        timestamp,
        ev.audit_id,
        ev.stage,
        ip,
        ev.verb,
        username,
        groups,
        asuser,
        asgroups,
        ev.user_agent,
        namespace,
        ev.request_uri,
        response
    )
}

/// 获取用户信息
fn get_user_info(ev: &audit_internal::Event) -> (String, String) {
    let username = if !ev.user.username.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
        ev.user.username.clone().unwrap_or_default()
    } else {
        NONE.to_string()
    };
    
    let groups = if let Some(user_groups) = &ev.user.groups {
        if !user_groups.is_empty() {
            audit_string_slice(user_groups)
        } else {
            NONE.to_string()
        }
    } else {
        NONE.to_string()
    };
    
    (username, groups)
}

/// 获取模拟用户信息
fn get_impersonated_user_info(ev: &audit_internal::Event) -> (String, String) {
    let asuser = if let Some(impersonated) = &ev.impersonated_user {
        if !impersonated.username.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
            impersonated.username.clone().unwrap_or_default()
        } else {
            SELF.to_string()
        }
    } else {
        SELF.to_string()
    };
    
    let asgroups = if let Some(impersonated) = &ev.impersonated_user {
        if let Some(groups) = &impersonated.groups {
            if !groups.is_empty() {
                audit_string_slice(groups)
            } else {
                LOOKUP.to_string()
            }
        } else {
            LOOKUP.to_string()
        }
    } else {
        LOOKUP.to_string()
    };
    
    (asuser, asgroups)
}

/// 获取命名空间
fn get_namespace(ev: &audit_internal::Event) -> String {
    if let Some(obj_ref) = &ev.object_ref {
        if !obj_ref.namespace.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
            obj_ref.namespace.clone().unwrap_or_default()
        } else {
            NONE.to_string()
        }
    } else {
        NONE.to_string()
    }
}

/// 获取响应状态
fn get_response_status(ev: &audit_internal::Event) -> String {
    if let Some(status) = &ev.response_status {
        if let Some(code) = status.code {
            code.to_string()
        } else {
            DEFERRED.to_string()
        }
    } else {
        DEFERRED.to_string()
    }
}

/// 获取源IP
fn get_source_ip(ev: &audit_internal::Event) -> String {
    if !ev.source_ips.is_empty() {
        ev.source_ips[0].clone()
    } else {
        UNKNOWN.to_string()
    }
}

/// 格式化时间戳
fn format_timestamp(timestamp: &audit_internal::MicroTime) -> String {
    // 注意：这里简化处理，实际应该使用chrono进行格式化
    // 假设MicroTime有to_rfc3339_nano方法
    timestamp.to_rfc3339_nano()
}

/// 将字符串切片格式化为带引号的逗号分隔字符串
fn audit_string_slice(in_list: &[String]) -> String {
    let quoted_elements: Vec<String> = in_list
        .iter()
        .map(|s| format!("\"{}\"", s))
        .collect();
    
    quoted_elements.join(",")
}

/// 将审计事件格式化为更易读的多行文本
/// 
/// # 参数
/// * `ev` - 审计事件
/// 
/// # 返回值
/// 多行格式化字符串
pub fn event_string_multiline(ev: &audit_internal::Event) -> String {
    let mut lines = Vec::new();
    
    // 基本信息
    lines.push(format!("审计事件 ID: {}", ev.audit_id));
    lines.push(format!("阶段: {:?}", ev.stage));
    lines.push(format!("时间戳: {}", format_timestamp(&ev.request_received_timestamp)));
    
    // 请求信息
    lines.push(format!("方法: {}", ev.verb));
    lines.push(format!("URI: {}", ev.request_uri));
    let user_agent = ev.user_agent.as_deref().unwrap_or("");
    lines.push(format!("User-Agent: {}", user_agent));
    
    // 用户信息
    let (username, groups) = get_user_info(ev);
    lines.push(format!("用户: {}", username));
    lines.push(format!("用户组: {}", groups));
    
    // 模拟用户信息
    let (asuser, asgroups) = get_impersonated_user_info(ev);
    lines.push(format!("模拟用户: {}", asuser));
    lines.push(format!("模拟用户组: {}", asgroups));
    
    // 源IP
    let ip = get_source_ip(ev);
    lines.push(format!("源IP: {}", ip));
    
    // 对象引用
    if let Some(obj_ref) = &ev.object_ref {
        lines.push("对象引用:".to_string());
        if let Some(namespace) = &obj_ref.namespace {
            lines.push(format!("  命名空间: {}", namespace));
        }
        if let Some(name) = &obj_ref.name {
            lines.push(format!("  名称: {}", name));
        }
        if let Some(resource) = &obj_ref.resource {
            lines.push(format!("  资源: {}", resource));
        }
        if let Some(subresource) = &obj_ref.subresource {
            lines.push(format!("  子资源: {}", subresource));
        }
        if let Some(api_group) = &obj_ref.api_group {
            lines.push(format!("  API组: {}", api_group));
        }
        if let Some(api_version) = &obj_ref.api_version {
            lines.push(format!("  API版本: {}", api_version));
        }
    }
    
    // 响应状态
    let response = get_response_status(ev);
    lines.push(format!("响应状态: {}", response));
    
    // 注解
    if !ev.annotations.is_empty() {
        lines.push("注解:".to_string());
        for (key, value) in &ev.annotations {
            lines.push(format!("  {}: {}", key, value));
        }
    }
    
    lines.join("\n")
}

/// 将审计事件格式化为JSON字符串
/// 
/// # 参数
/// * `ev` - 审计事件
/// 
/// # 返回值
/// JSON格式化字符串，如果序列化失败则返回错误
pub fn event_to_json(ev: &audit_internal::Event) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(ev)
}

/// 将审计事件格式化为YAML字符串
/// 
/// # 参数
/// * `ev` - 审计事件
/// 
/// # 返回值
/// YAML格式化字符串，如果序列化失败则返回错误
pub fn event_to_yaml(ev: &audit_internal::Event) -> Result<String, serde_yaml::Error> {
    serde_yaml::to_string(ev)
}

// ========== 测试模块 ==========

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_audit_apis::audit as audit_internal;
    
    /// 创建测试用的审计事件
    fn create_test_event() -> audit_internal::Event {
        audit_internal::Event {
            audit_id: "test-audit-id-123".to_string(),
            stage: audit_internal::Stage::RequestReceived,
            level: audit_internal::Level::Metadata,
            request_received_timestamp: audit_internal::MicroTime::now(),
            verb: "GET".to_string(),
            request_uri: "/api/v1/namespaces/default/pods".to_string(),
            user_agent: Some("kubectl/v1.25.0 (linux/amd64)".to_string()),
            source_ips: vec![
                "192.168.1.100".to_string(),
                "10.0.0.1".to_string(),
            ],
            user: audit_internal::UserInfo {
                username: Some("test-user".to_string()),
                uid: Some("test-uid".to_string()),
                groups: Some(vec![
                    "system:authenticated".to_string(),
                    "developers".to_string(),
                ]),
                extra: Some(std::collections::BTreeMap::new()),
                ..Default::default()
            },
            object_ref: Some(*Box::new(audit_internal::ObjectReference {
                namespace: Some("default".to_string()),
                name: Some("test-pod".to_string()),
                resource: Some("pods".to_string()),
                subresource: None,
                api_group: Some("".to_string()),
                api_version: Some("v1".to_string()),
                ..Default::default()
            })),
            response_status: Some(audit_internal::Status {
                code: Some(200),
                status: Some("Success".to_string()),
                message: None,
                reason: None,
                details: None,
            }),
            annotations: {
                let mut map = std::collections::HashMap::new();
                map.insert("key1".to_string(), "value1".to_string());
                map.insert("key2".to_string(), "value2".to_string());
                map
            },
            ..Default::default()
        }
    }
    
    /// 创建最小化的测试事件
    fn create_minimal_event() -> audit_internal::Event {
        audit_internal::Event {
            audit_id: "minimal-id".to_string(),
            stage: audit_internal::Stage::ResponseComplete,
            request_received_timestamp: audit_internal::MicroTime::now(),
            verb: "LIST".to_string(),
            request_uri: "/apis".to_string(),
            ..Default::default()
        }
    }
    
    #[test]
    fn test_event_string_full() {
        let event = create_test_event();
        let result = event_string(&event);
        
        // 验证包含关键字段
        assert!(result.contains("AUDIT:"));
        assert!(result.contains("id=\"test-audit-id-123\""));
        assert!(result.contains("stage=\"RequestReceived\""));
        assert!(result.contains("ip=\"192.168.1.100\""));
        assert!(result.contains("method=\"GET\""));
        assert!(result.contains("user=\"test-user\""));
        assert!(result.contains("groups=\"system:authenticated\",\"developers\""));
        assert!(result.contains("as=\"<self>\""));
        assert!(result.contains("asgroups=\"<lookup>\""));
        assert!(result.contains("user-agent=\"kubectl/v1.25.0 (linux/amd64)\""));
        assert!(result.contains("namespace=\"default\""));
        assert!(result.contains("uri=\"/api/v1/namespaces/default/pods\""));
        assert!(result.contains("response=\"200\""));
    }
    
    #[test]
    fn test_event_string_minimal() {
        let event = create_minimal_event();
        let result = event_string(&event);
        
        // 验证默认值
        assert!(result.contains("user=\"<none>\""));
        assert!(result.contains("groups=\"<none>\""));
        assert!(result.contains("as=\"<self>\""));
        assert!(result.contains("asgroups=\"<lookup>\""));
        assert!(result.contains("namespace=\"<none>\""));
        assert!(result.contains("response=\"<deferred>\""));
        assert!(result.contains("ip=\"<unknown>\""));
    }
    
    #[test]
    fn test_event_string_with_impersonated_user() {
        let mut event = create_test_event();
        
        // 添加模拟用户信息
        event.impersonated_user = Some(Box::new(audit_internal::UserInfo {
            username: Some("impersonated-user".to_string()),
            groups: Some(vec![
                "system:masters".to_string(),
                "admin".to_string(),
            ]),
            ..Default::default()
        }));
        
        let result = event_string(&event);
        
        assert!(result.contains("as=\"impersonated-user\""));
        assert!(result.contains("asgroups=\"system:masters\",\"admin\""));
    }
    
    #[test]
    fn test_event_string_with_empty_impersonated_groups() {
        let mut event = create_test_event();
        
        // 添加模拟用户但没有组
        event.impersonated_user = Some(Box::new(audit_internal::UserInfo {
            username: Some("impersonated-user".to_string()),
            groups: Some(vec![]), // 空组
            ..Default::default()
        }));
        
        let result = event_string(&event);
        
        assert!(result.contains("as=\"impersonated-user\""));
        assert!(result.contains("asgroups=\"<lookup>\""));
    }
    
    #[test]
    fn test_event_string_with_no_response_status() {
        let mut event = create_test_event();
        event.response_status = None;
        
        let result = event_string(&event);
        assert!(result.contains("response=\"<deferred>\""));
    }
    
    #[test]
    fn test_event_string_with_response_status_no_code() {
        let mut event = create_test_event();
        event.response_status = Some(audit_internal::Status {
            code: None,
            status: Some("Success".to_string()),
            ..Default::default()
        });
        
        let result = event_string(&event);
        assert!(result.contains("response=\"<deferred>\""));
    }
    
    #[test]
    fn test_event_string_with_empty_user() {
        let mut event = create_test_event();
        event.user = audit_internal::UserInfo::default();
        
        let result = event_string(&event);
        assert!(result.contains("user=\"<none>\""));
        assert!(result.contains("groups=\"<none>\""));
    }
    
    #[test]
    fn test_event_string_with_empty_username() {
        let mut event = create_test_event();
        event.user.username = Some("".to_string()); // 空用户名
        
        let result = event_string(&event);
        assert!(result.contains("user=\"<none>\""));
    }
    
    #[test]
    fn test_event_string_with_empty_namespace() {
        let mut event = create_test_event();
        if let Some(ref mut obj_ref) = event.object_ref {
            obj_ref.namespace = Some("".to_string()); // 空命名空间
        }
        
        let result = event_string(&event);
        assert!(result.contains("namespace=\"<none>\""));
    }
    
    #[test]
    fn test_event_string_without_object_ref() {
        let mut event = create_test_event();
        event.object_ref = None;
        
        let result = event_string(&event);
        assert!(result.contains("namespace=\"<none>\""));
    }
    
    #[test]
    fn test_audit_string_slice() {
        // 测试空切片
        let empty: Vec<String> = Vec::new();
        assert_eq!(audit_string_slice(&empty), "");
        
        // 测试单个元素
        let single = vec!["single".to_string()];
        assert_eq!(audit_string_slice(&single), "\"single\"");
        
        // 测试多个元素
        let multiple = vec![
            "first".to_string(),
            "second".to_string(),
            "third".to_string(),
        ];
        assert_eq!(audit_string_slice(&multiple), "\"first\",\"second\",\"third\"");
        
        // 测试包含特殊字符的元素
        let special = vec![
            "test\"quote".to_string(),
            "test,comma".to_string(),
        ];
        assert_eq!(audit_string_slice(&special), "\"test\\\"quote\",\"test,comma\"");
    }
    
    #[test]
    fn test_event_string_multiline() {
        let event = create_test_event();
        let result = event_string_multiline(&event);
        
        // 验证包含多行
        let lines: Vec<&str> = result.split('\n').collect();
        assert!(lines.len() > 10);
        
        // 验证关键信息存在
        assert!(result.contains("审计事件 ID: test-audit-id-123"));
        assert!(result.contains("阶段: RequestReceived"));
        assert!(result.contains("方法: GET"));
        assert!(result.contains("用户: test-user"));
        assert!(result.contains("用户组: \"system:authenticated\",\"developers\""));
        assert!(result.contains("命名空间: default"));
        assert!(result.contains("响应状态: 200"));
        
        // 验证注解存在
        assert!(result.contains("注解:"));
        assert!(result.contains("key1: value1"));
        assert!(result.contains("key2: value2"));
    }
    
    #[test]
    fn test_event_string_multiline_minimal() {
        let event = create_minimal_event();
        let result = event_string_multiline(&event);
        
        // 验证默认值
        assert!(result.contains("用户: <none>"));
        assert!(result.contains("用户组: <none>"));
        assert!(result.contains("模拟用户: <self>"));
        assert!(result.contains("模拟用户组: <lookup>"));
        assert!(result.contains("源IP: <unknown>"));
        assert!(result.contains("响应状态: <deferred>"));
    }
    
    #[test]
    fn test_event_to_json() {
        let event = create_test_event();
        let result = event_to_json(&event);
        
        assert!(result.is_ok());
        let json_str = result.unwrap();
        
        // 验证JSON可以解析
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["auditID"], "test-audit-id-123");
        assert_eq!(parsed["verb"], "GET");
        assert_eq!(parsed["requestURI"], "/api/v1/namespaces/default/pods");
    }
    
    #[test]
    fn test_event_to_yaml() {
        let event = create_test_event();
        let result = event_to_yaml(&event);
        
        assert!(result.is_ok());
        let yaml_str = result.unwrap();
        
        // 验证YAML包含关键字段
        assert!(yaml_str.contains("auditID: test-audit-id-123"));
        assert!(yaml_str.contains("verb: GET"));
        assert!(yaml_str.contains("requestURI: /api/v1/namespaces/default/pods"));
    }
    
    #[test]
    fn test_get_user_info() {
        let mut event = audit_internal::Event::default();
        
        // 测试没有用户信息
        let (username, groups) = get_user_info(&event);
        assert_eq!(username, "<none>");
        assert_eq!(groups, "<none>");
        
        // 测试有用户名但没有组
        event.user.username = Some("test-user".to_string());
        let (username, groups) = get_user_info(&event);
        assert_eq!(username, "test-user");
        assert_eq!(groups, "<none>");
        
        // 测试有用户名和组
        event.user.groups = Some(vec!["group1".to_string(), "group2".to_string()]);
        let (username, groups) = get_user_info(&event);
        assert_eq!(username, "test-user");
        assert_eq!(groups, "\"group1\",\"group2\"");
        
        // 测试空用户名
        event.user.username = Some("".to_string());
        let (username, _) = get_user_info(&event);
        assert_eq!(username, "<none>");
    }
    
    #[test]
    fn test_get_impersonated_user_info() {
        let mut event = audit_internal::Event::default();
        
        // 测试没有模拟用户
        let (asuser, asgroups) = get_impersonated_user_info(&event);
        assert_eq!(asuser, "<self>");
        assert_eq!(asgroups, "<lookup>");
        
        // 测试有模拟用户但没有组
        event.impersonated_user = Some(Box::new(audit_internal::UserInfo {
            username: Some("impersonated".to_string()),
            ..Default::default()
        }));
        
        let (asuser, asgroups) = get_impersonated_user_info(&event);
        assert_eq!(asuser, "impersonated");
        assert_eq!(asgroups, "<lookup>");
        
        // 测试有模拟用户和组
        event.impersonated_user = Some(Box::new(audit_internal::UserInfo {
            username: Some("impersonated".to_string()),
            groups: Some(vec!["admin".to_string(), "masters".to_string()]),
            ..Default::default()
        }));
        
        let (asuser, asgroups) = get_impersonated_user_info(&event);
        assert_eq!(asuser, "impersonated");
        assert_eq!(asgroups, "\"admin\",\"masters\"");
        
        // 测试空用户名
        event.impersonated_user = Some(Box::new(audit_internal::UserInfo {
            username: Some("".to_string()),
            ..Default::default()
        }));
        
        let (asuser, _) = get_impersonated_user_info(&event);
        assert_eq!(asuser, "<self>");
    }
    
    #[test]
    fn test_get_namespace() {
        let mut event = audit_internal::Event::default();
        
        // 测试没有对象引用
        assert_eq!(get_namespace(&event), "<none>");
        
        // 测试有对象引用但没有命名空间
        event.object_ref = Some(*Box::new(audit_internal::ObjectReference::default()));
        assert_eq!(get_namespace(&event), "<none>");
        
        // 测试有命名空间
        event.object_ref = Some(*Box::new(audit_internal::ObjectReference {
            namespace: Some("default".to_string()),
            ..Default::default()
        }));
        assert_eq!(get_namespace(&event), "default");
        
        // 测试空命名空间
        event.object_ref = Some(*Box::new(audit_internal::ObjectReference {
            namespace: Some("".to_string()),
            ..Default::default()
        }));
        assert_eq!(get_namespace(&event), "<none>");
    }
    
    #[test]
    fn test_get_response_status() {
        let mut event = audit_internal::Event::default();
        
        // 测试没有响应状态
        assert_eq!(get_response_status(&event), "<deferred>");
        
        // 测试有响应状态但没有代码
        event.response_status = Some(audit_internal::Status::default());
        assert_eq!(get_response_status(&event), "<deferred>");
        
        // 测试有响应代码
        event.response_status = Some(audit_internal::Status {
            code: Some(404),
            ..Default::default()
        });
        assert_eq!(get_response_status(&event), "404");
    }
    
    #[test]
    fn test_get_source_ip() {
        let mut event = audit_internal::Event::default();
        
        // 测试没有源IP
        assert_eq!(get_source_ip(&event), "<unknown>");
        
        // 测试有源IP
        event.source_ips = vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()];
        assert_eq!(get_source_ip(&event), "192.168.1.1");
    }
    
    #[test]
    fn test_format_timestamp() {
        let timestamp = audit_internal::MicroTime::now();
        let formatted = format_timestamp(&timestamp);
        
        // 验证格式大致正确（包含T和Z）
        assert!(formatted.contains('T'));
        assert!(formatted.contains('Z') || formatted.contains('+'));
    }
}