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

//! 审计策略验证
//!
//! 此模块包含审计策略的验证逻辑。

use std::fmt;
use std::string::ToString;

// 注意：thiserror 是可选的，如果特性未启用，我们手动实现 Error trait
#[cfg(feature = "thiserror")]
use thiserror::Error;

use crate::audit;

/// 验证错误类型
#[cfg_attr(feature = "thiserror", derive(Error))]
#[derive(Debug, Clone)]
pub enum ValidationError {
    /// 必填字段缺失
    #[cfg_attr(feature = "thiserror", error("field is required: {0}"))]
    Required(String),

    /// 不支持的字段值
    #[cfg_attr(
        feature = "thiserror",
        error("unsupported value: {0}, supported values: {1}")
    )]
    NotSupported(String, String),

    /// 无效的字段值
    #[cfg_attr(feature = "thiserror", error("invalid value at {0}: {1}"))]
    Invalid(String, String),

    /// 无效的字段组合
    #[cfg_attr(feature = "thiserror", error("invalid combination: {0}"))]
    InvalidCombination(String),
}

// 如果未启用 thiserror，手动实现 Display 和 std::error::Error
#[cfg(not(feature = "thiserror"))]
impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::Required(msg) => write!(f, "field is required: {}", msg),
            ValidationError::NotSupported(value, supported) => write!(
                f,
                "unsupported value: {}, supported values: {}",
                value, supported
            ),
            ValidationError::Invalid(path, msg) => write!(f, "invalid value at {}: {}", path, msg),
            ValidationError::InvalidCombination(msg) => write!(f, "invalid combination: {}", msg),
        }
    }
}

#[cfg(not(feature = "thiserror"))]
impl std::error::Error for ValidationError {}

/// 字段路径，用于标识错误发生的位置
#[derive(Debug, Clone)]
pub struct FieldPath {
    segments: Vec<String>,
}

impl FieldPath {
    /// 创建新的字段路径
    pub fn new(root: &str) -> Self {
        Self {
            segments: vec![root.to_string()],
        }
    }

    /// 添加子字段
    pub fn child(mut self, child: &str) -> Self {
        self.segments.push(child.to_string());
        self
    }

    /// 添加索引（用于数组）
    pub fn index(mut self, index: usize) -> Self {
        self.segments.push(format!("[{}]", index));
        self
    }

    /// 转换为字符串表示
    pub fn to_string(&self) -> String {
        self.segments.join(".")
    }
}

impl fmt::Display for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// 验证审计策略
///
/// # 参数
/// * `policy` - 要验证的审计策略
///
/// # 返回值
/// 验证错误列表，如果为空表示验证通过
pub fn validate_policy(policy: &audit::Policy) -> Vec<ValidationError> {
    let mut all_errors = Vec::new();

    // 验证 omitStages
    all_errors.extend(validate_omit_stages(
        &policy.omit_stages,
        FieldPath::new("omitStages"),
    ));

    // 验证规则
    let rule_path = FieldPath::new("rules");
    for (i, rule) in policy.rules.iter().enumerate() {
        all_errors.extend(validate_policy_rule(rule, rule_path.clone().index(i)));
    }

    all_errors
}

/// 验证单个策略规则
fn validate_policy_rule(rule: &audit::PolicyRule, fld_path: FieldPath) -> Vec<ValidationError> {
    let mut all_errors = Vec::new();

    all_errors.extend(validate_level(&rule.level, fld_path.clone().child("level")));
    all_errors.extend(validate_non_resource_urls(
        &rule.non_resource_urls,
        fld_path.clone().child("nonResourceURLs"),
    ));
    all_errors.extend(validate_resources(
        &rule.resources,
        fld_path.clone().child("resources"),
    ));
    all_errors.extend(validate_omit_stages(
        &rule.omit_stages,
        fld_path.clone().child("omitStages"),
    ));

    // 验证规则不能同时应用于常规资源和非资源URL
    if !rule.non_resource_urls.is_empty() {
        if !rule.resources.is_empty() || !rule.namespaces.is_empty() {
            all_errors.push(ValidationError::InvalidCombination(format!(
                "{}: rules cannot apply to both regular resources and non-resource URLs",
                fld_path.clone().child("nonResourceURLs")
            )));
        }
    }

    all_errors
}

/// 有效的审计级别
const _VALID_LEVELS: [&str; 4] = ["None", "Metadata", "Request", "RequestResponse"];

/// 有效的省略阶段
const VALID_OMIT_STAGES: [&str; 4] = [
    "RequestReceived",
    "ResponseStarted",
    "ResponseComplete",
    "Panic",
];

/// 验证审计级别
fn validate_level(level: &audit::Level, _fld_path: FieldPath) -> Vec<ValidationError> {
    match level {
        audit::Level::None
        | audit::Level::Metadata
        | audit::Level::Request
        | audit::Level::RequestResponse => Vec::new(),
        // _ => {
        //     // 简化处理：由于 Level 枚举是 exhaustive 的，这里实际上不会执行
        //     // 但为了完整性保留
        //     vec![ValidationError::Required(
        //         format!("{}: level is required", fld_path)
        //     )]
        // }
    }
}

/// 验证非资源URL
fn validate_non_resource_urls(urls: &[String], fld_path: FieldPath) -> Vec<ValidationError> {
    let mut all_errors = Vec::new();

    for (i, url) in urls.iter().enumerate() {
        let element_path = fld_path.clone().index(i);

        if url == "*" {
            continue;
        }

        // 非资源URL规则必须以'/'开头
        if !url.starts_with('/') {
            all_errors.push(ValidationError::Invalid(
                element_path.to_string(),
                format!(
                    "non-resource URL rules must begin with a '/' character: {}",
                    url
                ),
            ));
        }

        // 通配符'*'必须是规则的最后一个字符
        if url.len() > 1 && url[..url.len() - 1].contains('*') {
            all_errors.push(ValidationError::Invalid(
                element_path.to_string(),
                format!(
                    "non-resource URL wildcards '*' must be the final character of the rule: {}",
                    url
                ),
            ));
        }
    }

    all_errors
}

/// 验证资源定义
fn validate_resources(
    group_resources: &[audit::GroupResources],
    fld_path: FieldPath,
) -> Vec<ValidationError> {
    let mut all_errors = Vec::new();

    for (i, group_resource) in group_resources.iter().enumerate() {
        let resource_path = fld_path.clone().index(i);

        // 空字符串表示核心API组
        if let Some(ref group) = group_resource.group {
            if !group.is_empty() {
                // 简化验证：检查是否包含斜杠（表示版本）
                // k8s-openapi 中没有可用的验证函数，我们简化实现
                if group.contains('/') {
                    all_errors.push(ValidationError::Invalid(
                        resource_path.clone().child("group").to_string(),
                        format!("group name should not contain version: {}", group),
                    ));
                }
            }
        }

        // 如果指定了resourceNames，则必须至少有一个resource
        if !group_resource.resource_names.is_empty() && group_resource.resources.is_empty() {
            all_errors.push(ValidationError::Invalid(
                resource_path.clone().child("resourceNames").to_string(),
                "using resourceNames requires at least one resource".to_string(),
            ));
        }
    }

    all_errors
}

/// 验证省略阶段
fn validate_omit_stages(omit_stages: &[audit::Stage], fld_path: FieldPath) -> Vec<ValidationError> {
    let mut all_errors = Vec::new();

    for (i, stage) in omit_stages.iter().enumerate() {
        let _element_path = fld_path.clone().index(i);
        let stage_str = match stage {
            audit::Stage::RequestReceived => "RequestReceived",
            audit::Stage::ResponseStarted => "ResponseStarted",
            audit::Stage::ResponseComplete => "ResponseComplete",
            audit::Stage::Panic => "Panic",
        };

        if !VALID_OMIT_STAGES.contains(&stage_str) {
            all_errors.push(ValidationError::NotSupported(
                stage_str.to_string(),
                VALID_OMIT_STAGES.join(","),
            ));
        }
    }

    all_errors
}

/// 辅助函数：将验证错误转换为用户友好的消息
pub fn validation_errors_to_string(errors: &[ValidationError]) -> String {
    if errors.is_empty() {
        return "validation passed".to_string();
    }

    let mut messages = Vec::new();
    for error in errors {
        messages.push(format!("- {}", error));
    }

    format!(
        "Validation failed with {} error(s):\n{}",
        errors.len(),
        messages.join("\n")
    )
}

/// 验证结果类型，包含验证错误和警告
#[derive(Debug, Default)]
pub struct ValidationResult {
    /// 验证错误
    pub errors: Vec<ValidationError>,
    /// 验证警告
    pub warnings: Vec<String>,
}

impl ValidationResult {
    /// 创建新的验证结果
    pub fn new() -> Self {
        Self::default()
    }

    /// 添加错误
    pub fn add_error(&mut self, error: ValidationError) {
        self.errors.push(error);
    }

    /// 添加警告
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    /// 检查是否有效
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// 转换为字符串表示
    pub fn to_string(&self) -> String {
        if self.is_valid() {
            if self.warnings.is_empty() {
                "validation passed".to_string()
            } else {
                format!(
                    "validation passed with {} warning(s):\n{}",
                    self.warnings.len(),
                    self.warnings.join("\n")
                )
            }
        } else {
            validation_errors_to_string(&self.errors)
        }
    }
}

/// 验证审计策略，返回详细的验证结果
pub fn validate_policy_detailed(policy: &audit::Policy) -> ValidationResult {
    let mut result = ValidationResult::new();

    result.errors = validate_policy(policy);

    // 可以在这里添加警告检查
    // 例如：检查是否有冲突的规则，或者给出优化建议

    result
}
