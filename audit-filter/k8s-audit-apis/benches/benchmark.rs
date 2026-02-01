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

//! 性能基准测试
//!
//! 测量 k8s-audit-apis crate 的性能表现。

#![feature(test)]

extern crate test;

use k8s_audit_apis::audit;
use k8s_audit_apis::audit::validation;
use k8s_audit_apis::LevelExt;
use k8s_audit_apis::Status;
use test::Bencher;

/// 基准测试：创建审计事件
#[bench]
fn bench_event_creation(b: &mut Bencher) {
    b.iter(|| {
        let _event = audit::Event {
            level: audit::Level::Metadata,
            stage: audit::Stage::RequestReceived,
            audit_id: "benchmark-id".into(),
            request_uri: "/api/v1/pods".to_string(),
            verb: "list".to_string(),
            ..Default::default()
        };
    });
}

/// 基准测试：创建复杂审计事件
#[bench]
fn bench_complex_event_creation(b: &mut Bencher) {
    use k8s_audit_apis::MicroTime;
    use k8s_openapi::api::authentication::v1::UserInfo;

    let now = MicroTime::default();

    b.iter(|| {
        let _event = audit::Event {
            level: audit::Level::RequestResponse,
            stage: audit::Stage::ResponseComplete,
            audit_id: uuid::Uuid::new_v4().to_string().into(),
            request_uri: "/apis/apps/v1/namespaces/production/deployments".to_string(),
            verb: "create".to_string(),
            user: UserInfo {
                username: Some("bench-user".to_string()),
                uid: Some("12345".to_string()),
                groups: Some(vec!["admin".to_string(), "developers".to_string()]),
                extra: Some(
                    // 添加 Some() 包装
                    [("auth-provider".to_string(), vec!["oidc".to_string()])]
                        .iter()
                        .cloned()
                        .collect(),
                ),
                ..Default::default()
            },
            impersonated_user: Some(Box::new(UserInfo {
                username: Some("impersonated-user".to_string()),
                ..Default::default()
            })),
            source_ips: vec!["10.0.0.1".to_string(), "192.168.1.100".to_string()],
            user_agent: Some("kubectl/1.30.0".to_string()),
            object_ref: Some(audit::ObjectReference {
                resource: Some("deployments".to_string()),
                namespace: Some("production".to_string()),
                name: Some("bench-deployment".to_string()),
                api_group: Some("apps".to_string()),
                api_version: Some("v1".to_string()),
                ..Default::default()
            }),
            response_status: Some(Status {
                status: Some("Success".to_string()),
                code: Some(201),
                ..Default::default()
            }),
            request_received_timestamp: now.clone(),
            stage_timestamp: now.clone(),
            annotations: [("benchmark".to_string(), "true".to_string())]
                .iter()
                .cloned()
                .collect(),
            ..Default::default()
        };
    });
}

/// 基准测试：策略验证（简单策略）
#[bench]
fn bench_simple_policy_validation(b: &mut Bencher) {
    let policy = audit::Policy {
        rules: vec![audit::PolicyRule {
            level: audit::Level::Metadata,
            users: vec!["admin".to_string()],
            verbs: vec!["get".to_string()],
            resources: vec![audit::GroupResources {
                resources: vec!["pods".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    b.iter(|| {
        let _result = validation::validate_policy(&policy);
    });
}

/// 基准测试：策略验证（复杂策略）
#[bench]
fn bench_complex_policy_validation(b: &mut Bencher) {
    let policy = audit::Policy {
        rules: vec![
            audit::PolicyRule {
                level: audit::Level::RequestResponse,
                users: vec!["admin".to_string(), "system:admin".to_string()],
                user_groups: vec!["system:masters".to_string()],
                verbs: vec!["*".to_string()],
                resources: vec![
                    audit::GroupResources {
                        group: Some("".to_string()),
                        resources: vec![
                            "pods".to_string(),
                            "services".to_string(),
                            "secrets".to_string(),
                        ],
                        resource_names: vec!["default".to_string()],
                    },
                    audit::GroupResources {
                        group: Some("apps".to_string()),
                        resources: vec!["deployments".to_string(), "statefulsets".to_string()],
                        ..Default::default()
                    },
                    audit::GroupResources {
                        group: Some("networking.k8s.io".to_string()),
                        resources: vec!["ingresses".to_string()],
                        ..Default::default()
                    },
                ],
                namespaces: vec![
                    "production".to_string(),
                    "staging".to_string(),
                    "default".to_string(),
                ],
                non_resource_urls: vec!["/healthz".to_string(), "/metrics".to_string()],
                omit_stages: vec![audit::Stage::Panic, audit::Stage::ResponseStarted],
                omit_managed_fields: Some(true),
                ..Default::default()
            },
            audit::PolicyRule {
                level: audit::Level::Request,
                verbs: vec![
                    "create".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                ],
                resources: vec![audit::GroupResources {
                    resources: vec!["secrets".to_string()],
                    ..Default::default()
                }],
                ..Default::default()
            },
            audit::PolicyRule {
                level: audit::Level::Metadata,
                non_resource_urls: vec![
                    "/api".to_string(),
                    "/apis".to_string(),
                    "/openapi/*".to_string(),
                ],
                ..Default::default()
            },
        ],
        omit_stages: vec![audit::Stage::Panic],
        omit_managed_fields: Some(false),
        ..Default::default()
    };

    b.iter(|| {
        let _result = validation::validate_policy_detailed(&policy);
    });
}

/// 基准测试：JSON 序列化（如果启用了 serde）
#[cfg(feature = "serde")]
#[bench]
fn bench_json_serialization(b: &mut Bencher) {
    use serde_json;

    let event = audit::Event {
        level: audit::Level::RequestResponse,
        stage: audit::Stage::ResponseComplete,
        audit_id: "bench-serialization".into(),
        request_uri: "/api/v1/pods".to_string(),
        verb: "list".to_string(),
        user: k8s_openapi::api::authentication::v1::UserInfo {
            username: Some("bench-user".to_string()),
            ..Default::default()
        },
        source_ips: vec!["10.0.0.1".to_string()],
        object_ref: Some(audit::ObjectReference {
            resource: Some("pods".to_string()),
            ..Default::default()
        }),
        annotations: [
            ("key1".to_string(), "value1".to_string()),
            ("key2".to_string(), "value2".to_string()),
            ("key3".to_string(), "value3".to_string()),
        ]
        .iter()
        .cloned()
        .collect(),
        ..Default::default()
    };

    b.iter(|| {
        let _json = serde_json::to_string(&event).unwrap();
    });
}

/// 基准测试：批量事件处理
#[bench]
fn bench_batch_event_processing(b: &mut Bencher) {
    const BATCH_SIZE: usize = 1000;

    b.iter(|| {
        let mut events = Vec::with_capacity(BATCH_SIZE);

        for i in 0..BATCH_SIZE {
            events.push(audit::Event {
                audit_id: format!("batch-{}", i).into(),
                request_uri: format!("/api/v1/pods/{}", i),
                verb: if i % 2 == 0 {
                    "get".to_string()
                } else {
                    "list".to_string()
                },
                level: match i % 4 {
                    0 => audit::Level::None,
                    1 => audit::Level::Metadata,
                    2 => audit::Level::Request,
                    _ => audit::Level::RequestResponse,
                },
                stage: match i % 4 {
                    0 => audit::Stage::RequestReceived,
                    1 => audit::Stage::ResponseStarted,
                    2 => audit::Stage::ResponseComplete,
                    _ => audit::Stage::Panic,
                },
                ..Default::default()
            });
        }

        // 处理批次：排序、过滤等
        events.sort_by(|a, b| a.level.cmp(&b.level));
        let filtered: Vec<_> = events
            .iter()
            .filter(|e| e.level.greater_or_equal(&audit::Level::Request))
            .collect();

        assert_eq!(filtered.len(), BATCH_SIZE / 2);
    });
}

/// 基准测试：级别比较操作
#[bench]
fn bench_level_comparisons(b: &mut Bencher) {
    use audit::Level;

    let levels = vec![
        Level::None,
        Level::Metadata,
        Level::Request,
        Level::RequestResponse,
    ];

    b.iter(|| {
        let mut comparisons = 0;

        for i in 0..levels.len() {
            for j in 0..levels.len() {
                let _result = levels[i].less(&levels[j]);
                comparisons += 1;
            }
        }

        assert_eq!(comparisons, 16); // 4x4 矩阵
    });
}
