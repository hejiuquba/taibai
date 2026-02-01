/*
Copyright 2018 The Kubernetes Authors.

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

//! 策略工具函数
//!
//! 此模块提供审计策略相关的工具函数。

use std::collections::HashSet;
use k8s_audit_apis::audit as audit_internal;

/// 返回所有可能的审计阶段
pub fn all_stages() -> HashSet<String> {
    let mut stages = HashSet::new();
    stages.insert(audit_internal::Stage::RequestReceived.to_string());
    stages.insert(audit_internal::Stage::ResponseStarted.to_string());
    stages.insert(audit_internal::Stage::ResponseComplete.to_string());
    stages.insert(audit_internal::Stage::Panic.to_string());
    stages
}

/// 返回所有可能的审计级别
pub fn all_levels() -> HashSet<String> {
    let mut levels = HashSet::new();
    levels.insert(audit_internal::Level::None.to_string());
    levels.insert(audit_internal::Level::Metadata.to_string());
    levels.insert(audit_internal::Level::Request.to_string());
    levels.insert(audit_internal::Level::RequestResponse.to_string());
    levels
}

/// 反转阶段：从所有阶段中减去给定的阶段数组
pub fn invert_stages(stages: &[audit_internal::Stage]) -> Vec<audit_internal::Stage> {
    let stage_strings = convert_stages_to_strings(stages);
    let mut all_stages_set = all_stages();
    
    // 删除给定的阶段
    for stage in &stage_strings {
        all_stages_set.remove(stage);
    }
    
    convert_string_set_to_stages(&all_stages_set)
}

/// 将阶段数组转换为字符串数组
pub fn convert_stages_to_strings(stages: &[audit_internal::Stage]) -> Vec<String> {
    stages.iter()
        .map(|stage| stage.to_string())
        .collect()
}

/// 将字符串集合转换为阶段数组
pub fn convert_string_set_to_stages(set: &HashSet<String>) -> Vec<audit_internal::Stage> {
    set.iter()
        .filter_map(|s| {
            // 尝试解析字符串为阶段
            match s.as_str() {
                "RequestReceived" => Some(audit_internal::Stage::RequestReceived),
                "ResponseStarted" => Some(audit_internal::Stage::ResponseStarted),
                "ResponseComplete" => Some(audit_internal::Stage::ResponseComplete),
                "Panic" => Some(audit_internal::Stage::Panic),
                _ => None,
            }
        })
        .collect()
}

/// 检查阶段是否有效
pub fn is_valid_stage(stage: &audit_internal::Stage) -> bool {
    match stage {
        audit_internal::Stage::RequestReceived => true,
        audit_internal::Stage::ResponseStarted => true,
        audit_internal::Stage::ResponseComplete => true,
        audit_internal::Stage::Panic => true,
        // audit_internal::Stage::Unknown => false,
        // _ => false, // 处理可能的未来扩展
    }
}

/// 检查级别是否有效
pub fn is_valid_level(level: &audit_internal::Level) -> bool {
    match level {
        audit_internal::Level::None => true,
        audit_internal::Level::Metadata => true,
        audit_internal::Level::Request => true,
        audit_internal::Level::RequestResponse => true,
        // audit_internal::Level::Unknown => false,
        // _ => false, // 处理可能的未来扩展
    }
}

/// 合并多个阶段列表，去除重复项
pub fn merge_stages(stage_lists: &[Vec<audit_internal::Stage>]) -> Vec<audit_internal::Stage> {
    let mut stage_set = HashSet::new();
    
    for stages in stage_lists {
        for stage in stages {
            stage_set.insert(stage.clone());
        }
    }
    
    stage_set.into_iter().collect()
}