/*
Copyright 2024 The Kubernetes Authors.

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

//! 策略验证示例
//!
//! 展示如何创建和验证复杂的审计策略。

use k8s_audit_apis::audit;
use k8s_audit_apis::audit::validation;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== 审计策略验证示例 ===\n");

    // 1. 有效的策略示例
    println!("1. 有效策略示例:");
    let valid_policy = create_valid_policy();
    validate_and_print(&valid_policy);
    println!();

    // 2. 无效的策略示例
    println!("2. 无效策略示例:");
    let invalid_policy = create_invalid_policy();
    validate_and_print(&invalid_policy);
    println!();

    // 3. 边缘情况测试
    println!("3. 边缘情况测试:");
    test_edge_cases();
    println!();

    // 4. 复杂策略测试
    println!("4. 复杂策略测试:");
    test_complex_policy();

    Ok(())
}

/// 创建有效的审计策略
fn create_valid_policy() -> audit::Policy {
    audit::Policy {
        rules: vec![
            audit::PolicyRule {
                level: audit::Level::Request,
                users: vec!["admin".to_string()],
                verbs: vec![
                    "create".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                ],
                resources: vec![
                    audit::GroupResources {
                        group: Some("".to_string()),
                        resources: vec!["secrets".to_string(), "configmaps".to_string()],
                        resource_names: vec!["default-token".to_string()],
                    },
                    audit::GroupResources {
                        group: Some("apps".to_string()),
                        resources: vec!["deployments".to_string(), "statefulsets".to_string()],
                        ..Default::default()
                    },
                ],
                namespaces: vec!["production".to_string(), "staging".to_string()],
                ..Default::default()
            },
            audit::PolicyRule {
                level: audit::Level::Metadata,
                non_resource_urls: vec!["/metrics".to_string(), "/healthz".to_string()],
                ..Default::default()
            },
            audit::PolicyRule {
                level: audit::Level::RequestResponse,
                user_groups: vec!["system:masters".to_string()],
                verbs: vec!["*".to_string()],
                ..Default::default()
            },
        ],
        omit_stages: vec![audit::Stage::Panic],
        omit_managed_fields: Some(true),
        ..Default::default()
    }
}

/// 创建无效的审计策略
fn create_invalid_policy() -> audit::Policy {
    audit::Policy {
        rules: vec![
            audit::PolicyRule {
                level: audit::Level::Request,
                // 无效的组合：同时指定资源和 non_resource_urls
                resources: vec![audit::GroupResources {
                    resources: vec!["pods".to_string()],
                    ..Default::default()
                }],
                non_resource_urls: vec!["/api".to_string()], // 这会导致验证错误
                ..Default::default()
            },
            audit::PolicyRule {
                level: audit::Level::RequestResponse,
                // 无效的组名
                resources: vec![audit::GroupResources {
                    group: Some("apps/v1".to_string()), // 无效：包含版本
                    resources: vec!["deployments".to_string()],
                    ..Default::default()
                }],
                ..Default::default()
            },
            audit::PolicyRule {
                level: audit::Level::Metadata,
                // 无效的 non_resource_urls
                non_resource_urls: vec![
                    "metrics".to_string(),           // 缺少前导斜杠
                    "/healthz/*/detail".to_string(), // 中间有通配符
                ],
                ..Default::default()
            },
        ],
        // 无效的阶段
        omit_stages: vec![audit::Stage::Panic, audit::Stage::RequestReceived],
        ..Default::default()
    }
}

/// 验证并打印策略结果
fn validate_and_print(policy: &audit::Policy) {
    let result = validation::validate_policy_detailed(policy);

    println!("   策略包含 {} 条规则", policy.rules.len());

    if result.is_valid() {
        println!("   ✅ 验证通过");

        if !result.warnings.is_empty() {
            println!("   警告:");
            for warning in &result.warnings {
                println!("     - {}", warning);
            }
        }
    } else {
        println!("   ❌ 验证失败:");
        println!("   错误列表 ({} 个):", result.errors.len());

        for (i, error) in result.errors.iter().enumerate() {
            println!("     {}. {}", i + 1, error);
        }
    }
}

/// 测试边缘情况
fn test_edge_cases() {
    println!("   a. 空策略:");
    let empty_policy = audit::Policy::default();
    let empty_result = validation::validate_policy_detailed(&empty_policy);
    println!(
        "      验证结果: {}",
        if empty_result.is_valid() {
            "通过"
        } else {
            "失败"
        }
    );

    println!("   b. 只有默认级别的策略:");
    let default_level_policy = audit::Policy {
        rules: vec![audit::PolicyRule {
            level: audit::Level::None,
            ..Default::default()
        }],
        ..Default::default()
    };
    let default_result = validation::validate_policy_detailed(&default_level_policy);
    println!(
        "      验证结果: {}",
        if default_result.is_valid() {
            "通过"
        } else {
            "失败"
        }
    );

    println!("   c. 通配符资源测试:");
    let wildcard_policy = audit::Policy {
        rules: vec![audit::PolicyRule {
            level: audit::Level::Metadata,
            resources: vec![
                audit::GroupResources {
                    resources: vec!["*".to_string()],
                    ..Default::default()
                },
                audit::GroupResources {
                    resources: vec!["pods/*".to_string()],
                    ..Default::default()
                },
            ],
            ..Default::default()
        }],
        ..Default::default()
    };
    let wildcard_result = validation::validate_policy_detailed(&wildcard_policy);
    println!(
        "      验证结果: {}",
        if wildcard_result.is_valid() {
            "通过"
        } else {
            "失败"
        }
    );
}

/// 测试复杂策略
fn test_complex_policy() {
    use audit::Level;

    // 模拟真实场景的复杂策略
    let complex_policy = audit::Policy {
        rules: vec![
            // 规则1: 生产环境的所有写操作
            audit::PolicyRule {
                level: Level::RequestResponse,
                namespaces: vec!["prod".to_string(), "production".to_string()],
                verbs: vec![
                    "create".to_string(),
                    "update".to_string(),
                    "patch".to_string(),
                    "delete".to_string(),
                ],
                resources: vec![
                    audit::GroupResources {
                        group: Some("".to_string()),
                        resources: vec!["secrets".to_string(), "configmaps".to_string()],
                        ..Default::default()
                    },
                    audit::GroupResources {
                        group: Some("apps".to_string()),
                        resources: vec!["deployments".to_string()],
                        ..Default::default()
                    },
                ],
                omit_stages: vec![audit::Stage::ResponseStarted],
                ..Default::default()
            },
            // 规则2: 所有命名空间的敏感资源
            audit::PolicyRule {
                level: Level::Request,
                verbs: vec!["*".to_string()],
                resources: vec![audit::GroupResources {
                    resources: vec!["secrets".to_string()],
                    resource_names: vec!["*token*".to_string(), "*password*".to_string()],
                    ..Default::default()
                }],
                ..Default::default()
            },
            // 规则3: 服务账户的特殊处理
            audit::PolicyRule {
                level: Level::Metadata,
                users: vec!["system:serviceaccount:kube-system:default".to_string()],
                verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                ..Default::default()
            },
            // 规则4: 健康检查端点（非资源URL）
            audit::PolicyRule {
                level: Level::Metadata,
                non_resource_urls: vec![
                    "/healthz".to_string(),
                    "/readyz".to_string(),
                    "/livez".to_string(),
                ],
                omit_stages: vec![audit::Stage::Panic],
                ..Default::default()
            },
            // 规则5: 默认规则（捕获所有）
            audit::PolicyRule {
                level: Level::None,
                ..Default::default()
            },
        ],
        omit_managed_fields: Some(false),
        ..Default::default()
    };

    println!(
        "   创建包含 {} 条规则的复杂策略:",
        complex_policy.rules.len()
    );
    for (i, rule) in complex_policy.rules.iter().enumerate() {
        println!(
            "     规则 {}: 级别={:?}, 动词={:?}",
            i + 1,
            rule.level,
            rule.verbs
        );
    }

    let result = validation::validate_policy_detailed(&complex_policy);

    if result.is_valid() {
        println!("   ✅ 复杂策略验证通过！");
        println!("      警告数量: {}", result.warnings.len());
    } else {
        println!("   ❌ 复杂策略验证失败");
        println!("      错误数量: {}", result.errors.len());
    }
}
