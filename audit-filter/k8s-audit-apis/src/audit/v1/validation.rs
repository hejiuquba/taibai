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
use thiserror::Error;

use crate::audit;

/// 验证错误类型
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("field is required: {0}")]
    Required(String),

    #[error("unsupported value: {0}, supported values: {1}")]
    NotSupported(String, String),

    #[error("invalid value at {0}: {1}")]
    Invalid(String, String),

    #[error("invalid combination: {0}")]
    InvalidCombination(String),
}

/// 字段路径
#[derive(Debug, Clone)]
pub struct FieldPath {
    segments: Vec<String>,
}

impl FieldPath {
    pub fn new(root: &str) -> Self {
        Self {
            segments: vec![root.to_string()],
        }
    }

    pub fn child(mut self, child: &str) -> Self {
        self.segments.push(child.to_string());
        self
    }

    pub fn index(mut self, index: usize) -> Self {
        self.segments.push(format!("[{}]", index));
        self
    }

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

const _VALID_LEVELS: [&str; 4] = ["None", "Metadata", "Request", "RequestResponse"];
const VALID_OMIT_STAGES: [&str; 4] = [
    "RequestReceived",
    "ResponseStarted",
    "ResponseComplete",
    "Panic",
];

fn validate_level(level: &audit::Level, _fld_path: FieldPath) -> Vec<ValidationError> {
    match level {
        audit::Level::None
        | audit::Level::Metadata
        | audit::Level::Request
        | audit::Level::RequestResponse => Vec::new(),
        // _ => vec![ValidationError::Required(
        //     format!("{}: level is required", fld_path)
        // )],
    }
}

fn validate_non_resource_urls(urls: &[String], fld_path: FieldPath) -> Vec<ValidationError> {
    let mut all_errors = Vec::new();

    for (i, url) in urls.iter().enumerate() {
        let element_path = fld_path.clone().index(i);

        if url == "*" {
            continue;
        }

        if !url.starts_with('/') {
            all_errors.push(ValidationError::Invalid(
                element_path.to_string(),
                format!(
                    "non-resource URL rules must begin with a '/' character: {}",
                    url
                ),
            ));
        }

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

fn validate_resources(
    group_resources: &[audit::GroupResources],
    fld_path: FieldPath,
) -> Vec<ValidationError> {
    let mut all_errors = Vec::new();

    for (i, group_resource) in group_resources.iter().enumerate() {
        let resource_path = fld_path.clone().index(i);

        if let Some(ref group) = group_resource.group {
            if !group.is_empty() {
                // 简化验证：检查是否包含斜杠（表示版本）
                if group.contains('/') {
                    all_errors.push(ValidationError::Invalid(
                        resource_path.clone().child("group").to_string(),
                        format!("group name should not contain version: {}", group),
                    ));
                }
            }
        }

        if !group_resource.resource_names.is_empty() && group_resource.resources.is_empty() {
            all_errors.push(ValidationError::Invalid(
                resource_path.clone().child("resourceNames").to_string(),
                "using resourceNames requires at least one resource".to_string(),
            ));
        }
    }

    all_errors
}

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

/// 验证结果类型
#[derive(Debug, Default)]
pub struct ValidationResult {
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// 详细的策略验证
pub fn validate_policy_detailed(policy: &audit::Policy) -> ValidationResult {
    let mut result = ValidationResult::new();

    result.errors = validate_policy(policy);

    result
}
