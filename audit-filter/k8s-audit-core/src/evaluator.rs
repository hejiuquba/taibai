/*
Copyright 2021 The Kubernetes Authors.

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

//! 审计评估器
//!
//! 此模块定义了审计策略评估器接口，用于根据授权属性评估审计策略规则。

use k8s_audit_apis::audit as audit_internal;

/// 授权属性 trait
/// 
/// 对应 Go 接口：authorizer.Attributes
/// 这是一个简化版本，仅包含审计评估所需的基本属性
pub trait AuthorizerAttributes {
    /// 获取用户名称
    fn get_user(&self) -> Option<&str>;
    
    /// 获取用户组列表
    fn get_groups(&self) -> Vec<String>;
    
    /// 获取请求动词
    fn get_verb(&self) -> &str;
    
    /// 获取命名空间
    fn get_namespace(&self) -> Option<&str>;
    
    /// 获取API组
    fn get_api_group(&self) -> Option<&str>;
    
    /// 获取API版本
    fn get_api_version(&self) -> Option<&str>;
    
    /// 获取资源
    fn get_resource(&self) -> Option<&str>;
    
    /// 获取子资源
    fn get_subresource(&self) -> Option<&str>;
    
    /// 获取资源名称
    fn get_name(&self) -> Option<&str>;
    
    /// 是否是资源请求
    fn is_resource_request(&self) -> bool;
    
    /// 获取路径
    fn get_path(&self) -> Option<&str>;
}

/// 请求审计配置
/// 
/// 这是适用于给定请求的评估后的审计配置。
/// PolicyRuleEvaluator 根据授权属性评估审计策略，
/// 并返回适用于该请求的 RequestAuditConfig。
/// 
/// 注意：此结构体在 context.rs 中也定义，需要保持一致性。
/// 我们在这里重新导出以确保接口清晰。
pub type RequestAuditConfig = crate::context::RequestAuditConfig;

/// 策略规则评估器 trait
/// 
/// 公开用于评估策略规则的方法。
pub trait PolicyRuleEvaluator: Send + Sync {
    /// 根据给定的授权属性评估 API 服务器的审计策略，
    /// 并返回适用于给定请求的审计配置。
    fn evaluate_policy_rule(&self, attrs: &dyn AuthorizerAttributes) -> RequestAuditConfig;
}

/// 默认策略规则评估器实现
/// 
/// 这是一个简单的实现，总是返回默认配置。
/// 在实际使用中，应该实现具体的策略评估逻辑。
#[derive(Debug, Default)]
pub struct DefaultPolicyRuleEvaluator {
    /// 默认审计级别
    default_level: audit_internal::Level,
    /// 默认要省略的阶段
    default_omit_stages: Vec<audit_internal::Stage>,
    /// 是否默认省略托管字段
    default_omit_managed_fields: bool,
}

impl DefaultPolicyRuleEvaluator {
    /// 创建新的默认策略规则评估器
    pub fn new(
        level: audit_internal::Level,
        omit_stages: Vec<audit_internal::Stage>,
        omit_managed_fields: bool,
    ) -> Self {
        Self {
            default_level: level,
            default_omit_stages: omit_stages,
            default_omit_managed_fields: omit_managed_fields,
        }
    }
    
    /// 使用默认值创建评估器
    pub fn default_with(level: audit_internal::Level) -> Self {
        Self {
            default_level: level,
            default_omit_stages: Vec::new(),
            default_omit_managed_fields: false,
        }
    }
}

impl PolicyRuleEvaluator for DefaultPolicyRuleEvaluator {
    fn evaluate_policy_rule(&self, _attrs: &dyn AuthorizerAttributes) -> RequestAuditConfig {
        RequestAuditConfig {
            level: self.default_level.clone(),
            omit_stages: self.default_omit_stages.clone(),
            omit_managed_fields: self.default_omit_managed_fields,
        }
    }
}

/// 简单的授权属性实现，用于测试和演示
#[derive(Debug, Clone)]
pub struct SimpleAuthorizerAttributes {
    /// 用户名称
    pub user: Option<String>,
    /// 用户组
    pub groups: Vec<String>,
    /// 动词
    pub verb: String,
    /// 命名空间
    pub namespace: Option<String>,
    /// API 组
    pub api_group: Option<String>,
    /// API 版本
    pub api_version: Option<String>,
    /// 资源
    pub resource: Option<String>,
    /// 子资源
    pub subresource: Option<String>,
    /// 资源名称
    pub name: Option<String>,
    /// 是否是资源请求
    pub is_resource_request: bool,
    /// 路径
    pub path: Option<String>,
}

impl AuthorizerAttributes for SimpleAuthorizerAttributes {
    fn get_user(&self) -> Option<&str> {
        self.user.as_deref()
    }
    
    fn get_groups(&self) -> Vec<String> {
        self.groups.clone()
    }
    
    fn get_verb(&self) -> &str {
        &self.verb
    }
    
    fn get_namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }
    
    fn get_api_group(&self) -> Option<&str> {
        self.api_group.as_deref()
    }
    
    fn get_api_version(&self) -> Option<&str> {
        self.api_version.as_deref()
    }
    
    fn get_resource(&self) -> Option<&str> {
        self.resource.as_deref()
    }
    
    fn get_subresource(&self) -> Option<&str> {
        self.subresource.as_deref()
    }
    
    fn get_name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    
    fn is_resource_request(&self) -> bool {
        self.is_resource_request
    }
    
    fn get_path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

impl Default for SimpleAuthorizerAttributes {
    fn default() -> Self {
        Self {
            user: None,
            groups: Vec::new(),
            verb: "get".to_string(),
            namespace: None,
            api_group: None,
            api_version: None,
            resource: None,
            subresource: None,
            name: None,
            is_resource_request: true,
            path: None,
        }
    }
}