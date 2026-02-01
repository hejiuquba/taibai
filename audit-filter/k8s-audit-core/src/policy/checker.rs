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

//! 策略检查器
//!
//! 此模块实现了审计策略规则检查器，用于根据授权属性匹配策略规则。

use std::collections::HashSet;

use k8s_audit_apis::audit as audit_internal;
use crate::evaluator::{AuthorizerAttributes, PolicyRuleEvaluator, RequestAuditConfig};

/// 默认审计级别，如果没有匹配的策略规则，则使用此级别
pub const DEFAULT_AUDIT_LEVEL: audit_internal::Level = audit_internal::Level::None;

/// 创建新的策略规则评估器
/// 
/// 对应 Go 函数：NewPolicyRuleEvaluator
pub fn new_policy_rule_evaluator(policy: &audit_internal::Policy) -> Box<dyn PolicyRuleEvaluator> {
    // 注意：这里需要修改政策规则以合并阶段
    // 由于 Policy 是不可变的，我们需要创建副本
    let mut policy_copy = policy.clone();
    
    for rule in &mut policy_copy.rules {
        // 合并策略的 OmitStages 和规则的 OmitStages
        rule.omit_stages = union_stages(&[&policy.omit_stages, &rule.omit_stages]);
    }
    
    Box::new(PolicyRuleEvaluatorImpl {
        policy: policy_copy,
    })
}

/// 合并多个阶段列表，去除重复项
/// 
/// 对应 Go 函数：unionStages
fn union_stages(stage_lists: &[&Vec<audit_internal::Stage>]) -> Vec<audit_internal::Stage> {
    let mut stage_set = HashSet::new();
    
    for stages in stage_lists {
        for stage in *stages {
            stage_set.insert(stage.clone());
        }
    }
    
    stage_set.into_iter().collect()
}

/// 创建假的策略规则评估器，为所有请求返回常量级别（用于测试）
/// 
/// 对应 Go 函数：NewFakePolicyRuleEvaluator
pub fn new_fake_policy_rule_evaluator(
    level: audit_internal::Level,
    stages: Vec<audit_internal::Stage>,
) -> Box<dyn PolicyRuleEvaluator> {
    Box::new(FakePolicyRuleEvaluator {
        level,
        stages,
    })
}

/// 策略规则评估器实现
/// 
/// 对应 Go 类型：policyRuleEvaluator
struct PolicyRuleEvaluatorImpl {
    policy: audit_internal::Policy,
}

impl PolicyRuleEvaluator for PolicyRuleEvaluatorImpl {
    fn evaluate_policy_rule(&self, attrs: &dyn AuthorizerAttributes) -> RequestAuditConfig {
        for rule in &self.policy.rules {
            if rule_matches(rule, attrs) {
                return RequestAuditConfig {
                    level: rule.level.clone(),
                    omit_stages: rule.omit_stages.clone(),
                    omit_managed_fields: is_omit_managed_fields(rule, self.policy.omit_managed_fields.unwrap_or_default()),
                };
            }
        }
        
        // 没有规则匹配，返回默认配置
        RequestAuditConfig {
            level: DEFAULT_AUDIT_LEVEL,
            omit_stages: self.policy.omit_stages.clone(),
            omit_managed_fields: self.policy.omit_managed_fields.unwrap_or_default(),
        }
    }
}

/// 确定是否从请求和响应体中省略托管字段，不写入 API 审计日志
/// 
/// 如果用户在策略规则中指定了 OmitManagedFields，则覆盖策略中的全局默认值
fn is_omit_managed_fields(policy_rule: &audit_internal::PolicyRule, policy_default: bool) -> bool {
    match policy_rule.omit_managed_fields {
        Some(value) => value,
        None => policy_default,
    }
}

/// 检查规则是否与请求属性匹配
fn rule_matches(rule: &audit_internal::PolicyRule, attrs: &dyn AuthorizerAttributes) -> bool {
    // 检查用户匹配
    if !rule.users.is_empty() {
        let user_name = match attrs.get_user() {
            Some(name) => name,
            None => return false,
        };
        
        if !has_string(&rule.users, user_name) {
            return false;
        }
    }
    
    // 检查用户组匹配
    if !rule.user_groups.is_empty() {
        let user_groups = attrs.get_groups();
        if user_groups.is_empty() {
            return false;
        }
        
        let mut matched = false;
        for group in &user_groups {
            if has_string(&rule.user_groups, group) {
                matched = true;
                break;
            }
        }
        
        if !matched {
            return false;
        }
    }
    
    // 检查动词匹配
    if !rule.verbs.is_empty() {
        if !has_string(&rule.verbs, attrs.get_verb()) {
            return false;
        }
    }
    
    // 检查资源或命名空间匹配
    if !rule.namespaces.is_empty() || !rule.resources.is_empty() {
        return rule_matches_resource(rule, attrs);
    }
    
    // 检查非资源URL匹配
    if !rule.non_resource_urls.is_empty() {
        return rule_matches_non_resource(rule, attrs);
    }
    
    // 如果所有条件都为空，则匹配所有请求
    true
}

/// 检查规则的非资源URL是否与请求属性匹配
fn rule_matches_non_resource(rule: &audit_internal::PolicyRule, attrs: &dyn AuthorizerAttributes) -> bool {
    // 如果是资源请求，则不匹配非资源URL规则
    if attrs.is_resource_request() {
        return false;
    }
    
    let path = match attrs.get_path() {
        Some(p) => p,
        None => return false,
    };
    
    for spec in &rule.non_resource_urls {
        if path_matches(path, spec) {
            return true;
        }
    }
    
    false
}

/// 检查路径是否与路径规范匹配
fn path_matches(path: &str, spec: &str) -> bool {
    // 允许通配符匹配
    if spec == "*" {
        return true;
    }
    
    // 允许精确匹配
    if spec == path {
        return true;
    }
    
    // 允许尾随 * 子路径匹配
    if spec.ends_with('*') && path.starts_with(spec.trim_end_matches('*')) {
        return true;
    }
    
    false
}

/// 检查规则的资源字段是否与请求属性匹配
fn rule_matches_resource(rule: &audit_internal::PolicyRule, attrs: &dyn AuthorizerAttributes) -> bool {
    // 如果不是资源请求，则不匹配资源规则
    if !attrs.is_resource_request() {
        return false;
    }
    
    // 检查命名空间匹配
    if !rule.namespaces.is_empty() {
        let namespace = attrs.get_namespace().unwrap_or(""); // 非命名空间资源使用空字符串
        if !has_string(&rule.namespaces, namespace) {
            return false;
        }
    }
    
    // 如果没有指定资源，则只检查命名空间
    if rule.resources.is_empty() {
        return true;
    }
    
    let api_group = attrs.get_api_group();
    let resource = attrs.get_resource().unwrap_or("");
    let subresource = attrs.get_subresource().unwrap_or("");
    
    // 组合资源字符串
    let combined_resource = if !subresource.is_empty() {
        format!("{}/{}", resource, subresource)
    } else {
        resource.to_string()
    };
    
    let name = attrs.get_name().unwrap_or("");
    
    for gr in &rule.resources {
        if gr.group.as_deref() == api_group {
            // 如果资源列表为空，则匹配所有资源
            if gr.resources.is_empty() {
                return true;
            }
            
            for res in &gr.resources {
                // 检查资源名称匹配（如果指定了资源名称）
                if gr.resource_names.is_empty() || has_string(&gr.resource_names, name) {
                    // 匹配 "*"
                    if res == &combined_resource || res == "*" {
                        return true;
                    }
                    
                    // 匹配 "*/subresource"
                    if !subresource.is_empty() && res.starts_with("*/") {
                        let expected_subresource = res.trim_start_matches("*/");
                        if subresource == expected_subresource {
                            return true;
                        }
                    }
                    
                    // 匹配 "resource/*"
                    if res.ends_with("/*") {
                        let expected_resource = res.trim_end_matches("/*");
                        if resource == expected_resource {
                            return true;
                        }
                    }
                }
            }
        }
    }
    
    false
}

/// 工具函数：检查字符串切片是否包含特定字符串
fn has_string(slice: &[String], value: &str) -> bool {
    slice.iter().any(|s| s == value)
}

/// 假的策略规则评估器（用于测试）
struct FakePolicyRuleEvaluator {
    level: audit_internal::Level,
    stages: Vec<audit_internal::Stage>,
}

impl PolicyRuleEvaluator for FakePolicyRuleEvaluator {
    fn evaluate_policy_rule(&self, _attrs: &dyn AuthorizerAttributes) -> RequestAuditConfig {
        RequestAuditConfig {
            level: self.level.clone(),
            omit_stages: self.stages.clone(),
            omit_managed_fields: false, // 假评估器不支持 omit_managed_fields
        }
    }
}